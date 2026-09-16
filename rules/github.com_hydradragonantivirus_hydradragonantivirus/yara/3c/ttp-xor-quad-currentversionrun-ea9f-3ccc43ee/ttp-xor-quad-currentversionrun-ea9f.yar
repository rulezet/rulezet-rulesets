rule TTP_XOR_QUAD_CurrentVersionRun_ea9f {
  strings:
    $key_ea9f = { b9 f0 [2] 9d fe [2] b6 d2 [2] 98 f0 [2] 8c eb [2] 83 f1 [2] 9d ec [2] 9f ed [2] 84 eb [2] 98 ec [2] 84 c3 }

  condition:
    any of them
}