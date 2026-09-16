rule TTP_XOR_QUAD_CurrentVersionRun_f59f {
  strings:
    $key_f59f = { a6 f0 [2] 82 fe [2] a9 d2 [2] 87 f0 [2] 93 eb [2] 9c f1 [2] 82 ec [2] 80 ed [2] 9b eb [2] 87 ec [2] 9b c3 }

  condition:
    any of them
}