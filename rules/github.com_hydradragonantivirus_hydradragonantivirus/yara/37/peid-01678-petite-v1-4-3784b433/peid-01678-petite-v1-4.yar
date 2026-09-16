rule PEiD_01678_PEtite_v1_4_ {
  meta:
    description = "[PEtite v1.4]"
    ep_only     = "true"

  strings:
    $a = { 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 14 8B CC }

  condition:
    $a
}