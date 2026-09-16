rule TTP_XOR_QUAD_CurrentVersionRun_228a {
  strings:
    $key_228a = { 71 e5 [2] 55 eb [2] 7e c7 [2] 50 e5 [2] 44 fe [2] 4b e4 [2] 55 f9 [2] 57 f8 [2] 4c fe [2] 50 f9 [2] 4c d6 }

  condition:
    any of them
}