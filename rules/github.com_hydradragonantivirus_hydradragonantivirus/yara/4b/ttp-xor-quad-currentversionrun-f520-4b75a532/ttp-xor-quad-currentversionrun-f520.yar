rule TTP_XOR_QUAD_CurrentVersionRun_f520 {
  strings:
    $key_f520 = { a6 4f [2] 82 41 [2] a9 6d [2] 87 4f [2] 93 54 [2] 9c 4e [2] 82 53 [2] 80 52 [2] 9b 54 [2] 87 53 [2] 9b 7c }

  condition:
    any of them
}