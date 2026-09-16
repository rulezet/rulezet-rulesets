rule TTP_XOR_QUAD_CurrentVersionRun_628a {
  strings:
    $key_628a = { 31 e5 [2] 15 eb [2] 3e c7 [2] 10 e5 [2] 04 fe [2] 0b e4 [2] 15 f9 [2] 17 f8 [2] 0c fe [2] 10 f9 [2] 0c d6 }

  condition:
    any of them
}