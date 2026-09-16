rule PEiD_02136_Spalsher_1_0___3_0____Amok_ {
  meta:
    description = "[Spalsher 1.0 - 3.0 -> Amok]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 8B 44 24 24 E8 00 00 00 00 }

  condition:
    $a
}