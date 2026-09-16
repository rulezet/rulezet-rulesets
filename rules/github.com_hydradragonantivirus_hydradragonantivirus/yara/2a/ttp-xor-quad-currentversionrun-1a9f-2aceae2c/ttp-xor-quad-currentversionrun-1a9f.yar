rule TTP_XOR_QUAD_CurrentVersionRun_1a9f {
  strings:
    $key_1a9f = { 49 f0 [2] 6d fe [2] 46 d2 [2] 68 f0 [2] 7c eb [2] 73 f1 [2] 6d ec [2] 6f ed [2] 74 eb [2] 68 ec [2] 74 c3 }

  condition:
    any of them
}