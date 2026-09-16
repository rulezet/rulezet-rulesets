rule TTP_XOR_QUAD_CurrentVersionRun_e323 {
  strings:
    $key_e323 = { b0 4c [2] 94 42 [2] bf 6e [2] 91 4c [2] 85 57 [2] 8a 4d [2] 94 50 [2] 96 51 [2] 8d 57 [2] 91 50 [2] 8d 7f }

  condition:
    any of them
}