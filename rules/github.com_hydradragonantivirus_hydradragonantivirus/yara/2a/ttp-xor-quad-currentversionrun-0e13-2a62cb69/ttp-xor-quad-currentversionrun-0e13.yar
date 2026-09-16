rule TTP_XOR_QUAD_CurrentVersionRun_0e13 {
  strings:
    $key_0e13 = { 5d 7c [2] 79 72 [2] 52 5e [2] 7c 7c [2] 68 67 [2] 67 7d [2] 79 60 [2] 7b 61 [2] 60 67 [2] 7c 60 [2] 60 4f }

  condition:
    any of them
}