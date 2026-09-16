rule apt_nix_elf_Derusbi_Linux_Strings {

    meta:

      description = "Rule to detect APT Derusbi Linux Strings"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2017-05-31"
      rule_version = "v1"
      malware_type = "backdoor"
      malware_family = "Backdoor:ELF/Derusbi"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://attack.mitre.org/software/S0021/"

    strings:

        $a1 = "loadso" wide ascii fullword
        $a2 = "\nuname -a\n\n" wide ascii
        $a3 = "/dev/shm/.x11.id" wide ascii
        $a4 = "LxMain64" wide ascii nocase
        $a5 = "# \\u@\\h:\\w \\$ " wide ascii
        $b1 = "0123456789abcdefghijklmnopqrstuvwxyz" wide
        $b2 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" wide
        $b3 = "ret %d" wide fullword
        $b4 = "uname -a\n\n" wide ascii
        $b5 = "/proc/%u/cmdline" wide ascii
        $b6 = "/proc/self/exe" wide ascii
        $b7 = "cp -a %s %s" wide ascii
        $c1 = "/dev/pts/4" wide ascii fullword
        $c2 = "/tmp/1408.log" wide ascii fullword

    condition:

        uint32(0) == 0x464C457F and
        filesize < 200KB and
        ((1 of ($a*) and
        4 of ($b*)) or
        (1 of ($a*) and
        1 of ($c*)) or
        2 of ($a*) or
        all of ($b*))
}