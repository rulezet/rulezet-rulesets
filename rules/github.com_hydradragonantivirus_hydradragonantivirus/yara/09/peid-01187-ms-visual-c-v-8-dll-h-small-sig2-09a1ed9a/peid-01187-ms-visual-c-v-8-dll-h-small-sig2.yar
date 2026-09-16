rule PEiD_01187_MS_Visual_C___v_8_DLL__h_small_sig2__ {
  meta:
    description = "[MS Visual C++ v.8 DLL (h-small sig2)]"
    ep_only     = "true"

  strings:
    $a = { 8B FF 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 0F 84 ?? ?? 00 00 83 FE 01 }

  condition:
    $a
}