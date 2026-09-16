rule TTP_XOR_QUAD_CurrentVersionRun_749f {
  strings:
    $key_749f = { 27 f0 [2] 03 fe [2] 28 d2 [2] 06 f0 [2] 12 eb [2] 1d f1 [2] 03 ec [2] 01 ed [2] 1a eb [2] 06 ec [2] 1a c3 }

  condition:
    any of them
}