rule TTP_XOR_QUAD_CurrentVersionRun_4913 {
  strings:
    $key_4913 = { 1a 7c [2] 3e 72 [2] 15 5e [2] 3b 7c [2] 2f 67 [2] 20 7d [2] 3e 60 [2] 3c 61 [2] 27 67 [2] 3b 60 [2] 27 4f }

  condition:
    any of them
}