rule TTP_XOR_QUAD_CurrentVersionRun_f01a {
  strings:
    $key_f01a = { a3 75 [2] 87 7b [2] ac 57 [2] 82 75 [2] 96 6e [2] 99 74 [2] 87 69 [2] 85 68 [2] 9e 6e [2] 82 69 [2] 9e 46 }

  condition:
    any of them
}