rule PEiD_02085_Simple_UPX_Cryptor_v30_4_2005__multi_layer_encryption_ {
  meta:
    description = "[Simple UPX Cryptor v30.4.2005 [multi layer encryption]"
    ep_only     = "true"

  strings:
    $a = { 60 B8 ?? ?? ?? 00 B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }

  condition:
    $a
}