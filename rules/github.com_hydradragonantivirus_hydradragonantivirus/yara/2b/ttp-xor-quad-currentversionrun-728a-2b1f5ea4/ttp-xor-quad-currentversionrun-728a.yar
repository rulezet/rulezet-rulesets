rule TTP_XOR_QUAD_CurrentVersionRun_728a {
  strings:
    $key_728a = { 21 e5 [2] 05 eb [2] 2e c7 [2] 00 e5 [2] 14 fe [2] 1b e4 [2] 05 f9 [2] 07 f8 [2] 1c fe [2] 00 f9 [2] 1c d6 }

  condition:
    any of them
}