rule TTP_XOR_QUAD_CurrentVersionRun_364b {
  strings:
    $key_364b = { 65 24 [2] 41 2a [2] 6a 06 [2] 44 24 [2] 50 3f [2] 5f 25 [2] 41 38 [2] 43 39 [2] 58 3f [2] 44 38 [2] 58 17 }

  condition:
    any of them
}