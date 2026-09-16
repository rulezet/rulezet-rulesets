rule PEiD_01481_PCrypt_v3_51_ {
  meta:
    description = "[PCrypt v3.51]"
    ep_only     = "true"

  strings:
    $a = { 50 43 52 59 50 54 FF 76 33 2E 35 31 00 E9 }

  condition:
    $a
}