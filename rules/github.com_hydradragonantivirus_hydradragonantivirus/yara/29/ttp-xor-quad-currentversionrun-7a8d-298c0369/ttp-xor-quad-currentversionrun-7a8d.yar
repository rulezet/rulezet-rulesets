rule TTP_XOR_QUAD_CurrentVersionRun_7a8d {
  strings:
    $key_7a8d = { 29 e2 [2] 0d ec [2] 26 c0 [2] 08 e2 [2] 1c f9 [2] 13 e3 [2] 0d fe [2] 0f ff [2] 14 f9 [2] 08 fe [2] 14 d1 }

  condition:
    any of them
}