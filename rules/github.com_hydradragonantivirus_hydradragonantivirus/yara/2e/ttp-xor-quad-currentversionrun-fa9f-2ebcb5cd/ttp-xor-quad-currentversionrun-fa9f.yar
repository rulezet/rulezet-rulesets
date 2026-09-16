rule TTP_XOR_QUAD_CurrentVersionRun_fa9f {
  strings:
    $key_fa9f = { a9 f0 [2] 8d fe [2] a6 d2 [2] 88 f0 [2] 9c eb [2] 93 f1 [2] 8d ec [2] 8f ed [2] 94 eb [2] 88 ec [2] 94 c3 }

  condition:
    any of them
}