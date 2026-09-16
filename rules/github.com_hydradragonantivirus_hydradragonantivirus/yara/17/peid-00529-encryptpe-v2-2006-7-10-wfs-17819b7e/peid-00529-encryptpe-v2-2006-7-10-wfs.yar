rule PEiD_00529_EncryptPE_V2_2006_7_10____WFS_ {
  meta:
    description = "[EncryptPE V2.2006.7.10 -> WFS]"
    ep_only     = "false"

  strings:
    $a = { 60 9C 64 FF 35 00 00 00 00 E8 73 01 00 00 }

  condition:
    $a
}