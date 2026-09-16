rule TTP_XOR_QUAD_CurrentVersionRun_339f {
  strings:
    $key_339f = { 60 f0 [2] 44 fe [2] 6f d2 [2] 41 f0 [2] 55 eb [2] 5a f1 [2] 44 ec [2] 46 ed [2] 5d eb [2] 41 ec [2] 5d c3 }

  condition:
    any of them
}