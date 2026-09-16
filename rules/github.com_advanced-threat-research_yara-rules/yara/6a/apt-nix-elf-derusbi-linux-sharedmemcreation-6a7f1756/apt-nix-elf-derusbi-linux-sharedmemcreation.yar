rule apt_nix_elf_Derusbi_Linux_SharedMemCreation {

    meta:

      description = "Rule to detect Derusbi Linux Shared Memory creation"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2017-05-31"
      rule_version = "v1"
      malware_type = "backdoor"
      malware_family = "Backdoor:ELF/Derusbi"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://attack.mitre.org/software/S0021/"

    strings:

        $byte1 = { B6 03 00 00 ?? 40 00 00 00 ?? 0D 5F 01 82 }

    condition:

        (uint32(0) == 0x464C457F) and
        filesize < 200KB and
        all of them
}