rule TTP_XOR_QUAD_CurrentVersionRun_f21d {
  strings:
    $key_f21d = { a1 72 [2] 85 7c [2] ae 50 [2] 80 72 [2] 94 69 [2] 9b 73 [2] 85 6e [2] 87 6f [2] 9c 69 [2] 80 6e [2] 9c 41 }

  condition:
    any of them
}