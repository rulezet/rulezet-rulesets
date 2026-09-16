rule TTP_XOR_QUAD_CurrentVersionRun_4613 {
  strings:
    $key_4613 = { 15 7c [2] 31 72 [2] 1a 5e [2] 34 7c [2] 20 67 [2] 2f 7d [2] 31 60 [2] 33 61 [2] 28 67 [2] 34 60 [2] 28 4f }

  condition:
    any of them
}