rule PEiD_00599_EXECryptor_2_0_2_1__protected_IAT_____www_strongbit_com_ {
  meta:
    description = "[EXECryptor 2.0/2.1 (protected IAT) -> www.strongbit.com]"
    ep_only     = "true"

  strings:
    $a = { A4 ?? ?? ?? 00 00 00 00 FF FF FF FF 3C ?? ?? ?? 94 ?? ?? ?? D8 ?? ?? ?? 00 00 00 00 FF FF FF FF B8 ?? ?? ?? D4 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 }

  condition:
    $a
}