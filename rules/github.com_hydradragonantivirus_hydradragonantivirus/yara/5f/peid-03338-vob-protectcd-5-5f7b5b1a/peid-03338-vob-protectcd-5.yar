rule PEiD_03338_VOB_ProtectCD_5_ {
  meta:
    description = "[VOB ProtectCD 5]"
    ep_only     = "true"

  strings:
    $a = { 36 3E 26 8A C0 60 E8 }

  condition:
    $a
}