rule TTP_XOR_QUAD_CurrentVersionRun_f08a {
  strings:
    $key_f08a = { a3 e5 [2] 87 eb [2] ac c7 [2] 82 e5 [2] 96 fe [2] 99 e4 [2] 87 f9 [2] 85 f8 [2] 9e fe [2] 82 f9 [2] 9e d6 }

  condition:
    any of them
}