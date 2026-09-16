rule PEiD_01748_PolyCryptor_by_SMT_Version__v3__v4_ {
  meta:
    description = "[PolyCryptor by SMT Version %v3.%v4]"
    ep_only     = "true"

  strings:
    $a = { EB ?? 28 50 6F 6C 79 53 63 72 79 70 74 20 ?? ?? ?? 20 62 79 20 53 4D 54 29 }

  condition:
    $a
}