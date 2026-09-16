rule TTP_XOR_QUAD_CurrentVersionRun_428a {
  strings:
    $key_428a = { 11 e5 [2] 35 eb [2] 1e c7 [2] 30 e5 [2] 24 fe [2] 2b e4 [2] 35 f9 [2] 37 f8 [2] 2c fe [2] 30 f9 [2] 2c d6 }

  condition:
    any of them
}