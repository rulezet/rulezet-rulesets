rule TTP_XOR_QUAD_CurrentVersionRun_419f {
  strings:
    $key_419f = { 12 f0 [2] 36 fe [2] 1d d2 [2] 33 f0 [2] 27 eb [2] 28 f1 [2] 36 ec [2] 34 ed [2] 2f eb [2] 33 ec [2] 2f c3 }

  condition:
    any of them
}