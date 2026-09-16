rule TTP_XOR_QUAD_CurrentVersionRun_f413 {
  strings:
    $key_f413 = { a7 7c [2] 83 72 [2] a8 5e [2] 86 7c [2] 92 67 [2] 9d 7d [2] 83 60 [2] 81 61 [2] 9a 67 [2] 86 60 [2] 9a 4f }

  condition:
    any of them
}