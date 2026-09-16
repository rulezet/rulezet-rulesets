rule TTP_XOR_QUAD_CurrentVersionRun_f313 {
  strings:
    $key_f313 = { a0 7c [2] 84 72 [2] af 5e [2] 81 7c [2] 95 67 [2] 9a 7d [2] 84 60 [2] 86 61 [2] 9d 67 [2] 81 60 [2] 9d 4f }

  condition:
    any of them
}