rule TTP_XOR_QUAD_CurrentVersionRun_258a {
  strings:
    $key_258a = { 76 e5 [2] 52 eb [2] 79 c7 [2] 57 e5 [2] 43 fe [2] 4c e4 [2] 52 f9 [2] 50 f8 [2] 4b fe [2] 57 f9 [2] 4b d6 }

  condition:
    any of them
}