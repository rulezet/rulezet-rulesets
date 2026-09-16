rule TTP_XOR_QUAD_CurrentVersionRun_f213 {
  strings:
    $key_f213 = { a1 7c [2] 85 72 [2] ae 5e [2] 80 7c [2] 94 67 [2] 9b 7d [2] 85 60 [2] 87 61 [2] 9c 67 [2] 80 60 [2] 9c 4f }

  condition:
    any of them
}