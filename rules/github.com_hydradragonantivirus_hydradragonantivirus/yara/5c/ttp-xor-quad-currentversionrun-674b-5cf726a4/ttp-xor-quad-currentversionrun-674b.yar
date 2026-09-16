rule TTP_XOR_QUAD_CurrentVersionRun_674b {
  strings:
    $key_674b = { 34 24 [2] 10 2a [2] 3b 06 [2] 15 24 [2] 01 3f [2] 0e 25 [2] 10 38 [2] 12 39 [2] 09 3f [2] 15 38 [2] 09 17 }

  condition:
    any of them
}