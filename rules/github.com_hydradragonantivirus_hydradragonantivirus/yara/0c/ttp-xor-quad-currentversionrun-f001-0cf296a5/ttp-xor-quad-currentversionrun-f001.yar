rule TTP_XOR_QUAD_CurrentVersionRun_f001 {
  strings:
    $key_f001 = { a3 6e [2] 87 60 [2] ac 4c [2] 82 6e [2] 96 75 [2] 99 6f [2] 87 72 [2] 85 73 [2] 9e 75 [2] 82 72 [2] 9e 5d }

  condition:
    any of them
}