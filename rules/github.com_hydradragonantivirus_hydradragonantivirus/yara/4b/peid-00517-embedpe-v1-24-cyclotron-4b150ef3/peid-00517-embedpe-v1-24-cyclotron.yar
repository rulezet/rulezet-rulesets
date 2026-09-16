rule PEiD_00517_EmbedPE_v1_24____cyclotron_ {
  meta:
    description = "[EmbedPE v1.24 -> cyclotron]"
    ep_only     = "true"

  strings:
    $a = { 83 EC 50 60 68 ?? ?? ?? ?? E8 CB FF 00 00 }

  condition:
    $a
}