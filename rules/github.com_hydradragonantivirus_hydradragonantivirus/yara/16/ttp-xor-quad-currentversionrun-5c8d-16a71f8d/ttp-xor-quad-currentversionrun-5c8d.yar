rule TTP_XOR_QUAD_CurrentVersionRun_5c8d {
  strings:
    $key_5c8d = { 0f e2 [2] 2b ec [2] 00 c0 [2] 2e e2 [2] 3a f9 [2] 35 e3 [2] 2b fe [2] 29 ff [2] 32 f9 [2] 2e fe [2] 32 d1 }

  condition:
    any of them
}