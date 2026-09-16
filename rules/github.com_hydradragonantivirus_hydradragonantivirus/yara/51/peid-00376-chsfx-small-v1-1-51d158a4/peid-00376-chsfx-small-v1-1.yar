rule PEiD_00376_ChSfx__small__v1_1_ {
  meta:
    description = "[ChSfx (small) v1.1]"
    ep_only     = "true"

  strings:
    $a = { BA ?? ?? E8 ?? ?? 8B EC 83 EC ?? 8C C8 BB ?? ?? B1 ?? D3 EB 03 C3 8E D8 05 ?? ?? 89 }

  condition:
    $a
}