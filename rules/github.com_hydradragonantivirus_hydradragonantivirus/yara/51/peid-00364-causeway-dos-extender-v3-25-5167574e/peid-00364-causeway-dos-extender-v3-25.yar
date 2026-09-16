rule PEiD_00364_CauseWay_DOS_Extender_v3_25_ {
  meta:
    description = "[CauseWay DOS Extender v3.25]"
    ep_only     = "true"

  strings:
    $a = { FA 16 1F 26 ?? ?? ?? 83 ?? ?? 8E D0 FB 06 16 07 BE ?? ?? 8B FE B9 ?? ?? F3 A4 07 }

  condition:
    $a
}