rule PEiD_02171_SVK_Protector_v1_051_ {
  meta:
    description = "[SVK-Protector v1.051]"
    ep_only     = "true"

  strings:
    $a = { 60 EB 03 C7 84 E8 EB 03 C7 84 9A E8 00 00 00 00 5D 81 ED 10 00 00 00 EB 03 C7 84 E9 64 A0 23 00 00 00 EB }

  condition:
    $a
}