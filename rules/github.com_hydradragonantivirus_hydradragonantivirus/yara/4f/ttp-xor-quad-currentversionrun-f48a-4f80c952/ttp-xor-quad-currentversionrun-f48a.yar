rule TTP_XOR_QUAD_CurrentVersionRun_f48a {
  strings:
    $key_f48a = { a7 e5 [2] 83 eb [2] a8 c7 [2] 86 e5 [2] 92 fe [2] 9d e4 [2] 83 f9 [2] 81 f8 [2] 9a fe [2] 86 f9 [2] 9a d6 }

  condition:
    any of them
}