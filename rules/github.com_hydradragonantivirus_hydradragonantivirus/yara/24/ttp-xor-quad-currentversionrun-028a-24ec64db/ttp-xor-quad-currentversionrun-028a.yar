rule TTP_XOR_QUAD_CurrentVersionRun_028a {
  strings:
    $key_028a = { 51 e5 [2] 75 eb [2] 5e c7 [2] 70 e5 [2] 64 fe [2] 6b e4 [2] 75 f9 [2] 77 f8 [2] 6c fe [2] 70 f9 [2] 6c d6 }

  condition:
    any of them
}