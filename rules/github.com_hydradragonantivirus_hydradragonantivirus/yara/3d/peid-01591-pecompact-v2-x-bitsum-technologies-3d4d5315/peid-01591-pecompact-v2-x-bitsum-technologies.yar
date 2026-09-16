rule PEiD_01591_PECompact_V2_X____Bitsum_Technologies_ {
  meta:
    description = "[PECompact V2.X -> Bitsum Technologies]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 }

  condition:
    $a
}