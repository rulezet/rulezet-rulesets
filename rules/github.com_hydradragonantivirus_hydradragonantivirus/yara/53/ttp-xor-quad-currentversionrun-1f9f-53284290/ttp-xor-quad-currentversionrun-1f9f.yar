rule TTP_XOR_QUAD_CurrentVersionRun_1f9f {
  strings:
    $key_1f9f = { 4c f0 [2] 68 fe [2] 43 d2 [2] 6d f0 [2] 79 eb [2] 76 f1 [2] 68 ec [2] 6a ed [2] 71 eb [2] 6d ec [2] 71 c3 }

  condition:
    any of them
}