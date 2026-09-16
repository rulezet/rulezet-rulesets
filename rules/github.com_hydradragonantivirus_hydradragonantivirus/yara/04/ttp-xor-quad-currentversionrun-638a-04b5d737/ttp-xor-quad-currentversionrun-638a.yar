rule TTP_XOR_QUAD_CurrentVersionRun_638a {
  strings:
    $key_638a = { 30 e5 [2] 14 eb [2] 3f c7 [2] 11 e5 [2] 05 fe [2] 0a e4 [2] 14 f9 [2] 16 f8 [2] 0d fe [2] 11 f9 [2] 0d d6 }

  condition:
    any of them
}