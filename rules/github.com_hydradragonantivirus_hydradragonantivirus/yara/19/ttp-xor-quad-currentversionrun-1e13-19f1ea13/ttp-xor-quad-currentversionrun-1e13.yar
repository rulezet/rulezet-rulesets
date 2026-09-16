rule TTP_XOR_QUAD_CurrentVersionRun_1e13 {
  strings:
    $key_1e13 = { 4d 7c [2] 69 72 [2] 42 5e [2] 6c 7c [2] 78 67 [2] 77 7d [2] 69 60 [2] 6b 61 [2] 70 67 [2] 6c 60 [2] 70 4f }

  condition:
    any of them
}