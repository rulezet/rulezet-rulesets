rule PEiD_01712_PKLITE_v1_14__v1_20_ {
  meta:
    description = "[PKLITE v1.14, v1.20]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 09 BA ?? ?? CD 21 CD 20 }

  condition:
    $a
}