rule TTP_XOR_QUAD_CurrentVersionRun_fc9f {
  strings:
    $key_fc9f = { af f0 [2] 8b fe [2] a0 d2 [2] 8e f0 [2] 9a eb [2] 95 f1 [2] 8b ec [2] 89 ed [2] 92 eb [2] 8e ec [2] 92 c3 }

  condition:
    any of them
}