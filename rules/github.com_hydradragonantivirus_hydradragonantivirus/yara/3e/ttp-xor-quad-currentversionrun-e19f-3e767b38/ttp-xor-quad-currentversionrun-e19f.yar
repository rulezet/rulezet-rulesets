rule TTP_XOR_QUAD_CurrentVersionRun_e19f {
  strings:
    $key_e19f = { b2 f0 [2] 96 fe [2] bd d2 [2] 93 f0 [2] 87 eb [2] 88 f1 [2] 96 ec [2] 94 ed [2] 8f eb [2] 93 ec [2] 8f c3 }

  condition:
    any of them
}