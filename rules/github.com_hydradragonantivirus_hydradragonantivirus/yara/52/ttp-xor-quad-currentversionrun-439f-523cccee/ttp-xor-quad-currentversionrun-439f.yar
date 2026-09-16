rule TTP_XOR_QUAD_CurrentVersionRun_439f {
  strings:
    $key_439f = { 10 f0 [2] 34 fe [2] 1f d2 [2] 31 f0 [2] 25 eb [2] 2a f1 [2] 34 ec [2] 36 ed [2] 2d eb [2] 31 ec [2] 2d c3 }

  condition:
    any of them
}