rule TTP_XOR_QUAD_CurrentVersionRun_764b {
  strings:
    $key_764b = { 25 24 [2] 01 2a [2] 2a 06 [2] 04 24 [2] 10 3f [2] 1f 25 [2] 01 38 [2] 03 39 [2] 18 3f [2] 04 38 [2] 18 17 }

  condition:
    any of them
}