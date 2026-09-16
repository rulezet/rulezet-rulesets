rule TTP_XOR_QUAD_CurrentVersionRun_3a8d {
  strings:
    $key_3a8d = { 69 e2 [2] 4d ec [2] 66 c0 [2] 48 e2 [2] 5c f9 [2] 53 e3 [2] 4d fe [2] 4f ff [2] 54 f9 [2] 48 fe [2] 54 d1 }

  condition:
    any of them
}