rule TTP_XOR_QUAD_CurrentVersionRun_0f23 {
  strings:
    $key_0f23 = { 5c 4c [2] 78 42 [2] 53 6e [2] 7d 4c [2] 69 57 [2] 66 4d [2] 78 50 [2] 7a 51 [2] 61 57 [2] 7d 50 [2] 61 7f }

  condition:
    any of them
}