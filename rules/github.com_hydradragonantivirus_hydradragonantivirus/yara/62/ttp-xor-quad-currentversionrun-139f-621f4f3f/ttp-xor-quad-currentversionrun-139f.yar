rule TTP_XOR_QUAD_CurrentVersionRun_139f {
  strings:
    $key_139f = { 40 f0 [2] 64 fe [2] 4f d2 [2] 61 f0 [2] 75 eb [2] 7a f1 [2] 64 ec [2] 66 ed [2] 7d eb [2] 61 ec [2] 7d c3 }

  condition:
    any of them
}