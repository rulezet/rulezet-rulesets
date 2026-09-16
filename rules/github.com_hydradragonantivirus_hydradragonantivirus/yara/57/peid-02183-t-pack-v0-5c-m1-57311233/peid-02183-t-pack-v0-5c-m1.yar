rule PEiD_02183_T_PACK_v0_5c__m1_ {
  meta:
    description = "[T-PACK v0.5c -m1]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 8E FE }

  condition:
    $a
}