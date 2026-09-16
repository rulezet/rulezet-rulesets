rule TTP_XOR_QUAD_CurrentVersionRun_338a {
  strings:
    $key_338a = { 60 e5 [2] 44 eb [2] 6f c7 [2] 41 e5 [2] 55 fe [2] 5a e4 [2] 44 f9 [2] 46 f8 [2] 5d fe [2] 41 f9 [2] 5d d6 }

  condition:
    any of them
}