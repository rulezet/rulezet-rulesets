rule TTP_XOR_QUAD_CurrentVersionRun_0e23 {
  strings:
    $key_0e23 = { 5d 4c [2] 79 42 [2] 52 6e [2] 7c 4c [2] 68 57 [2] 67 4d [2] 79 50 [2] 7b 51 [2] 60 57 [2] 7c 50 [2] 60 7f }

  condition:
    any of them
}