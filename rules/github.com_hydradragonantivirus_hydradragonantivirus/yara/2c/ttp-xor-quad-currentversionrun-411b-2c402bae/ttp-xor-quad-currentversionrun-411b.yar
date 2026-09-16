rule TTP_XOR_QUAD_CurrentVersionRun_411b {
  strings:
    $key_411b = { 12 74 [2] 36 7a [2] 1d 56 [2] 33 74 [2] 27 6f [2] 28 75 [2] 36 68 [2] 34 69 [2] 2f 6f [2] 33 68 [2] 2f 47 }

  condition:
    any of them
}