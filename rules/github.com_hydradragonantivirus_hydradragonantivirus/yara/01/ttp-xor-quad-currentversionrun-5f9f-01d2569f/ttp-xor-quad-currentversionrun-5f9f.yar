rule TTP_XOR_QUAD_CurrentVersionRun_5f9f {
  strings:
    $key_5f9f = { 0c f0 [2] 28 fe [2] 03 d2 [2] 2d f0 [2] 39 eb [2] 36 f1 [2] 28 ec [2] 2a ed [2] 31 eb [2] 2d ec [2] 31 c3 }

  condition:
    any of them
}