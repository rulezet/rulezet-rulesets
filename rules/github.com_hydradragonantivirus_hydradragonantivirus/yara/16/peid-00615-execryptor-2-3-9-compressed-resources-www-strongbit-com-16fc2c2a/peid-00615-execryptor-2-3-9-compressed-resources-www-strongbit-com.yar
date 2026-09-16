rule PEiD_00615_EXECryptor_2_3_9__compressed_resources_____www_strongbit_com_ {
  meta:
    description = "[EXECryptor 2.3.9 (compressed resources) -> www.strongbit.com]"
    ep_only     = "false"

  strings:
    $a = { 51 68 ?? ?? ?? ?? 59 81 F1 12 3C CB 98 E9 53 2C 00 00 F7 D7 E9 EB 60 00 00 83 45 F8 02 E9 E3 36 00 00 F6 45 F8 20 0F 84 1E 21 00 00 55 E9 80 62 00 00 87 0C 24 8B E9 ?? ?? ?? ?? 00 00 23 C1 81 E9 ?? ?? ?? ?? 57 E9 ED 00 00 00 0F 88 ?? ?? ?? ?? E9 2C 0D 00 }

  condition:
    $a
}