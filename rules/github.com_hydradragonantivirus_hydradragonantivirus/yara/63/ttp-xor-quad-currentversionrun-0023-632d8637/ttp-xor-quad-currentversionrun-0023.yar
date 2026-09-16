rule TTP_XOR_QUAD_CurrentVersionRun_0023 {
  strings:
    $key_0023 = { 53 4c [2] 77 42 [2] 5c 6e [2] 72 4c [2] 66 57 [2] 69 4d [2] 77 50 [2] 75 51 [2] 6e 57 [2] 72 50 [2] 6e 7f }

  condition:
    any of them
}