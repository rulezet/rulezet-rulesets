rule TTP_XOR_QUAD_CurrentVersionRun_f07d {
  strings:
    $key_f07d = { a3 12 [2] 87 1c [2] ac 30 [2] 82 12 [2] 96 09 [2] 99 13 [2] 87 0e [2] 85 0f [2] 9e 09 [2] 82 0e [2] 9e 21 }

  condition:
    any of them
}