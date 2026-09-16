rule TTP_XOR_QUAD_CurrentVersionRun_f21a {
  strings:
    $key_f21a = { a1 75 [2] 85 7b [2] ae 57 [2] 80 75 [2] 94 6e [2] 9b 74 [2] 85 69 [2] 87 68 [2] 9c 6e [2] 80 69 [2] 9c 46 }

  condition:
    any of them
}