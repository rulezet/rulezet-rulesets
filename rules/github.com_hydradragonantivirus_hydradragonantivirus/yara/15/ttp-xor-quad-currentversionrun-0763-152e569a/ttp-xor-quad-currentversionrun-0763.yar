rule TTP_XOR_QUAD_CurrentVersionRun_0763 {
  strings:
    $key_0763 = { 54 0c [2] 70 02 [2] 5b 2e [2] 75 0c [2] 61 17 [2] 6e 0d [2] 70 10 [2] 72 11 [2] 69 17 [2] 75 10 [2] 69 3f }

  condition:
    any of them
}