rule TTP_XOR_QUAD_CurrentVersionRun_138a {
  strings:
    $key_138a = { 40 e5 [2] 64 eb [2] 4f c7 [2] 61 e5 [2] 75 fe [2] 7a e4 [2] 64 f9 [2] 66 f8 [2] 7d fe [2] 61 f9 [2] 7d d6 }

  condition:
    any of them
}