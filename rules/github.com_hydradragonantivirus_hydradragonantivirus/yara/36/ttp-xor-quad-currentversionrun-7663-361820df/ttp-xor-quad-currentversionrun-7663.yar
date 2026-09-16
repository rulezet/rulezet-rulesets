rule TTP_XOR_QUAD_CurrentVersionRun_7663 {
  strings:
    $key_7663 = { 25 0c [2] 01 02 [2] 2a 2e [2] 04 0c [2] 10 17 [2] 1f 0d [2] 01 10 [2] 03 11 [2] 18 17 [2] 04 10 [2] 18 3f }

  condition:
    any of them
}