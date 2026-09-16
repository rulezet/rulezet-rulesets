rule TTP_XOR_QUAD_CurrentVersionRun_1677 {
  strings:
    $key_1677 = { 45 18 [2] 61 16 [2] 4a 3a [2] 64 18 [2] 70 03 [2] 7f 19 [2] 61 04 [2] 63 05 [2] 78 03 [2] 64 04 [2] 78 2b }

  condition:
    any of them
}