rule PEiD_01542_PeCompact_2_53_DLL__Slim_Loader_____BitSum_Technologies_ {
  meta:
    description = "[PeCompact 2.53 DLL (Slim Loader) -> BitSum Technologies]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 00 08 0C 00 48 E1 01 56 57 53 55 8B 5C 24 1C 85 DB 0F 84 AB 21 E8 BD 0E E6 60 0D 0B 6B 65 72 6E 6C 33 32 }

  condition:
    $a
}