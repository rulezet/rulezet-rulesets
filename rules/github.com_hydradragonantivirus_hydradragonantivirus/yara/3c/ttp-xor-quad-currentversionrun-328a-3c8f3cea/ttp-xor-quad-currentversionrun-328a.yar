rule TTP_XOR_QUAD_CurrentVersionRun_328a {
  strings:
    $key_328a = { 61 e5 [2] 45 eb [2] 6e c7 [2] 40 e5 [2] 54 fe [2] 5b e4 [2] 45 f9 [2] 47 f8 [2] 5c fe [2] 40 f9 [2] 5c d6 }

  condition:
    any of them
}