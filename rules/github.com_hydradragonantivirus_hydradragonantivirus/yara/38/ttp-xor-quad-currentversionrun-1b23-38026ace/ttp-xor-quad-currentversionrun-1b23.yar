rule TTP_XOR_QUAD_CurrentVersionRun_1b23 {
  strings:
    $key_1b23 = { 48 4c [2] 6c 42 [2] 47 6e [2] 69 4c [2] 7d 57 [2] 72 4d [2] 6c 50 [2] 6e 51 [2] 75 57 [2] 69 50 [2] 75 7f }

  condition:
    any of them
}