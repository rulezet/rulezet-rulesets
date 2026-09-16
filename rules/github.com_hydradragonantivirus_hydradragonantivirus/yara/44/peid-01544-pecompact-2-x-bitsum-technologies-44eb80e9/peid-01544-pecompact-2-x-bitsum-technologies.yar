rule PEiD_01544_PECompact_2_x____Bitsum_Technologies_ {
  meta:
    description = "[PECompact 2.x -> Bitsum Technologies]"
    ep_only     = "false"

  strings:
    $a = { B8 ?? ?? ?? 02 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }

  condition:
    $a
}