rule PEiD_00635_EXECryptor_V2_2X____softcomplete_com_ {
  meta:
    description = "[EXECryptor V2.2X -> softcomplete.com]"
    ep_only     = "false"

  strings:
    $a = { FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 00 }

  condition:
    $a
}