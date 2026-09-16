rule TTP_XOR_QUAD_CurrentVersionRun_3a9f {
  strings:
    $key_3a9f = { 69 f0 [2] 4d fe [2] 66 d2 [2] 48 f0 [2] 5c eb [2] 53 f1 [2] 4d ec [2] 4f ed [2] 54 eb [2] 48 ec [2] 54 c3 }

  condition:
    any of them
}