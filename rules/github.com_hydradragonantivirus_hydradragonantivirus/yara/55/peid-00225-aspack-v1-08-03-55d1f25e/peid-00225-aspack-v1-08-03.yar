rule PEiD_00225_ASPack_v1_08_03_ {
  meta:
    description = "[ASPack v1.08.03]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD }

  condition:
    $a
}