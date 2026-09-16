rule TTP_XOR_QUAD_CurrentVersionRun_e28d {
  strings:
    $key_e28d = { b1 e2 [2] 95 ec [2] be c0 [2] 90 e2 [2] 84 f9 [2] 8b e3 [2] 95 fe [2] 97 ff [2] 8c f9 [2] 90 fe [2] 8c d1 }

  condition:
    any of them
}