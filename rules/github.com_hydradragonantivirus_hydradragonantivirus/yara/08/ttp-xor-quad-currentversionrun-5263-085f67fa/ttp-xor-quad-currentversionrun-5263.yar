rule TTP_XOR_QUAD_CurrentVersionRun_5263 {
  strings:
    $key_5263 = { 01 0c [2] 25 02 [2] 0e 2e [2] 20 0c [2] 34 17 [2] 3b 0d [2] 25 10 [2] 27 11 [2] 3c 17 [2] 20 10 [2] 3c 3f }

  condition:
    any of them
}