rule TTP_XOR_QUAD_CurrentVersionRun_0b23 {
  strings:
    $key_0b23 = { 58 4c [2] 7c 42 [2] 57 6e [2] 79 4c [2] 6d 57 [2] 62 4d [2] 7c 50 [2] 7e 51 [2] 65 57 [2] 79 50 [2] 65 7f }

  condition:
    any of them
}