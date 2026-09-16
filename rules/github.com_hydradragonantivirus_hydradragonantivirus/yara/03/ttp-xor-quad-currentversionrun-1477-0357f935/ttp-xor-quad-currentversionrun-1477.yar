rule TTP_XOR_QUAD_CurrentVersionRun_1477 {
  strings:
    $key_1477 = { 47 18 [2] 63 16 [2] 48 3a [2] 66 18 [2] 72 03 [2] 7d 19 [2] 63 04 [2] 61 05 [2] 7a 03 [2] 66 04 [2] 7a 2b }

  condition:
    any of them
}