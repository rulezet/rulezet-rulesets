rule TTP_XOR_QUAD_CurrentVersionRun_0703 {
  strings:
    $key_0703 = { 54 6c [2] 70 62 [2] 5b 4e [2] 75 6c [2] 61 77 [2] 6e 6d [2] 70 70 [2] 72 71 [2] 69 77 [2] 75 70 [2] 69 5f }

  condition:
    any of them
}