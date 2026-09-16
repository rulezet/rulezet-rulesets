rule TTP_XOR_QUAD_CurrentVersionRun_f4ec {
  strings:
    $key_f4ec = { a7 83 [2] 83 8d [2] a8 a1 [2] 86 83 [2] 92 98 [2] 9d 82 [2] 83 9f [2] 81 9e [2] 9a 98 [2] 86 9f [2] 9a b0 }

  condition:
    any of them
}