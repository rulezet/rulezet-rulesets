rule TTP_XOR_QUAD_CurrentVersionRun_278a {
  strings:
    $key_278a = { 74 e5 [2] 50 eb [2] 7b c7 [2] 55 e5 [2] 41 fe [2] 4e e4 [2] 50 f9 [2] 52 f8 [2] 49 fe [2] 55 f9 [2] 49 d6 }

  condition:
    any of them
}