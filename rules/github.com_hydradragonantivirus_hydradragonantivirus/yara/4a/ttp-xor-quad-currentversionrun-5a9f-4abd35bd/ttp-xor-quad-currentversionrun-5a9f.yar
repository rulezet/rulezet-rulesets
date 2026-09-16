rule TTP_XOR_QUAD_CurrentVersionRun_5a9f {
  strings:
    $key_5a9f = { 09 f0 [2] 2d fe [2] 06 d2 [2] 28 f0 [2] 3c eb [2] 33 f1 [2] 2d ec [2] 2f ed [2] 34 eb [2] 28 ec [2] 34 c3 }

  condition:
    any of them
}