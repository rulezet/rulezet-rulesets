rule PEiD_01615_PEncrypt_1_0____JunkCode_ {
  meta:
    description = "[PEncrypt 1.0 -> JunkCode]"
    ep_only     = "true"

  strings:
    $a = { 60 9C BE 00 10 40 00 8B FE B9 ?? ?? ?? ?? BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 E9 ?? ?? ?? FF }

  condition:
    $a
}