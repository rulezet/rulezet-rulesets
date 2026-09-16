rule TTP_XOR_QUAD_CurrentVersionRun_4c13 {
  strings:
    $key_4c13 = { 1f 7c [2] 3b 72 [2] 10 5e [2] 3e 7c [2] 2a 67 [2] 25 7d [2] 3b 60 [2] 39 61 [2] 22 67 [2] 3e 60 [2] 22 4f }

  condition:
    any of them
}