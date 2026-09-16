rule TTP_XOR_QUAD_CurrentVersionRun_6f9f {
  strings:
    $key_6f9f = { 3c f0 [2] 18 fe [2] 33 d2 [2] 1d f0 [2] 09 eb [2] 06 f1 [2] 18 ec [2] 1a ed [2] 01 eb [2] 1d ec [2] 01 c3 }

  condition:
    any of them
}