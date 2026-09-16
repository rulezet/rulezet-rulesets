rule PEiD_01706_PKLITE_v1_00__v1_03_ {
  meta:
    description = "[PKLITE v1.00, v1.03]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? BA ?? ?? 8C DB 03 D8 3B }

  condition:
    $a
}