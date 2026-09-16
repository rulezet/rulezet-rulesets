rule PEiD_01085_Microsoft_Visual_C___8_0__MFC__ {
  meta:
    description = "[Microsoft Visual C++ 8.0 (MFC)]"
    ep_only     = "true"

  strings:
    $a = { 48 83 EC 28 E8 ?? ?? 00 00 48 83 C4 28 E9 0E FD FF FF CC CC CC CC CC CC CC CC CC CC CC CC CC CC }

  condition:
    $a
}