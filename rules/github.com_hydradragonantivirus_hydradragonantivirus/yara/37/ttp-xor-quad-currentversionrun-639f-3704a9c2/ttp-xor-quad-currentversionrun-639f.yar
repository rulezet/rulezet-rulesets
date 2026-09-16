rule TTP_XOR_QUAD_CurrentVersionRun_639f {
  strings:
    $key_639f = { 30 f0 [2] 14 fe [2] 3f d2 [2] 11 f0 [2] 05 eb [2] 0a f1 [2] 14 ec [2] 16 ed [2] 0d eb [2] 11 ec [2] 0d c3 }

  condition:
    any of them
}