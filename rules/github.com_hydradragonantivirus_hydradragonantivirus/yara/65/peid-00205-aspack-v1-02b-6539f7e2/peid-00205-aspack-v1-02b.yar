rule PEiD_00205_ASPack_v1_02b_ {
  meta:
    description = "[ASPack v1.02b]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 C5 2B 85 7D 7C 43 ?? 89 85 89 7C 43 ?? 80 BD 74 7C 43 }

  condition:
    $a
}