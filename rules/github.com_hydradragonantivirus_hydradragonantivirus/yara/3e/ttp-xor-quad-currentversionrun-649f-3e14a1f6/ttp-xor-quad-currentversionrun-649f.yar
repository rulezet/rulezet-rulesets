rule TTP_XOR_QUAD_CurrentVersionRun_649f {
  strings:
    $key_649f = { 37 f0 [2] 13 fe [2] 38 d2 [2] 16 f0 [2] 02 eb [2] 0d f1 [2] 13 ec [2] 11 ed [2] 0a eb [2] 16 ec [2] 0a c3 }

  condition:
    any of them
}