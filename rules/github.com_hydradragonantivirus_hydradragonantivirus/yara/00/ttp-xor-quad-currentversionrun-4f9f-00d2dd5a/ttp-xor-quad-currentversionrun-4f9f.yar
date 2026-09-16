rule TTP_XOR_QUAD_CurrentVersionRun_4f9f {
  strings:
    $key_4f9f = { 1c f0 [2] 38 fe [2] 13 d2 [2] 3d f0 [2] 29 eb [2] 26 f1 [2] 38 ec [2] 3a ed [2] 21 eb [2] 3d ec [2] 21 c3 }

  condition:
    any of them
}