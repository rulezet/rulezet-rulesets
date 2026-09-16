rule TTP_XOR_QUAD_CurrentVersionRun_5049 {
  strings:
    $key_5049 = { 03 26 [2] 27 28 [2] 0c 04 [2] 22 26 [2] 36 3d [2] 39 27 [2] 27 3a [2] 25 3b [2] 3e 3d [2] 22 3a [2] 3e 15 }

  condition:
    any of them
}