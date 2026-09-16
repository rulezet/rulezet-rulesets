rule TTP_XOR_QUAD_CurrentVersionRun_ea8d {
  strings:
    $key_ea8d = { b9 e2 [2] 9d ec [2] b6 c0 [2] 98 e2 [2] 8c f9 [2] 83 e3 [2] 9d fe [2] 9f ff [2] 84 f9 [2] 98 fe [2] 84 d1 }

  condition:
    any of them
}