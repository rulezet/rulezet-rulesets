rule TTP_XOR_QUAD_CurrentVersionRun_134b {
  strings:
    $key_134b = { 40 24 [2] 64 2a [2] 4f 06 [2] 61 24 [2] 75 3f [2] 7a 25 [2] 64 38 [2] 66 39 [2] 7d 3f [2] 61 38 [2] 7d 17 }

  condition:
    any of them
}