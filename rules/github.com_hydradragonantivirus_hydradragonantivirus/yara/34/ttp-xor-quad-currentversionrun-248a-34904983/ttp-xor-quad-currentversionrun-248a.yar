rule TTP_XOR_QUAD_CurrentVersionRun_248a {
  strings:
    $key_248a = { 77 e5 [2] 53 eb [2] 78 c7 [2] 56 e5 [2] 42 fe [2] 4d e4 [2] 53 f9 [2] 51 f8 [2] 4a fe [2] 56 f9 [2] 4a d6 }

  condition:
    any of them
}