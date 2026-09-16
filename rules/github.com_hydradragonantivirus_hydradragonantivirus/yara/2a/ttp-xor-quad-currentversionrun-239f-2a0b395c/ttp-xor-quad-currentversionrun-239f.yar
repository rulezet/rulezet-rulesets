rule TTP_XOR_QUAD_CurrentVersionRun_239f {
  strings:
    $key_239f = { 70 f0 [2] 54 fe [2] 7f d2 [2] 51 f0 [2] 45 eb [2] 4a f1 [2] 54 ec [2] 56 ed [2] 4d eb [2] 51 ec [2] 4d c3 }

  condition:
    any of them
}