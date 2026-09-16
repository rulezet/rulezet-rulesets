rule TTP_XOR_QUAD_CurrentVersionRun_0293 {
  strings:
    $key_0293 = { 51 fc [2] 75 f2 [2] 5e de [2] 70 fc [2] 64 e7 [2] 6b fd [2] 75 e0 [2] 77 e1 [2] 6c e7 [2] 70 e0 [2] 6c cf }

  condition:
    any of them
}