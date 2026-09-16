rule PEiD_01589_PECompact_v2_5_Retail__Slim_Loader_____Bitsum_Technologies_ {
  meta:
    description = "[PECompact v2.5 Retail (Slim Loader) -> Bitsum Technologies]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }

  condition:
    $a
}