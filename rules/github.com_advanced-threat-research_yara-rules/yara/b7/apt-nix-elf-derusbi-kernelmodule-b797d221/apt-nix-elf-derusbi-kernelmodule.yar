rule apt_nix_elf_derusbi_kernelModule {

    meta:

      description = "Rule to detect the Derusbi ELK Kernel module"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2017-05-31"
      rule_version = "v1"
      malware_type = "backdoor"
      malware_family = "Backdoor:ELF/Derusbi"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://attack.mitre.org/software/S0021/"

    strings:

        $s1 = "__this_module"
        $s2 = "init_module"
        $s3 = "unhide_pid"
        $s4 = "is_hidden_pid"
        $s5 = "clear_hidden_pid"
        $s6 = "hide_pid"
        $s7 = "license"
        $s8 = "description"
        $s9 = "srcversion="
        $s10 = "depends="
        $s11 = "vermagic="
        $s12 = "current_task"
        $s13 = "sock_release"
        $s14 = "module_layout"
        $s15 = "init_uts_ns"
        $s16 = "init_net"
        $s17 = "init_task"
        $s18 = "filp_open"
        $s19 = "__netlink_kernel_create"
        $s20 = "kfree_skb"

    condition:

        (uint32(0) == 0x4464c457f) and
        filesize < 200KB and
        all of them
}