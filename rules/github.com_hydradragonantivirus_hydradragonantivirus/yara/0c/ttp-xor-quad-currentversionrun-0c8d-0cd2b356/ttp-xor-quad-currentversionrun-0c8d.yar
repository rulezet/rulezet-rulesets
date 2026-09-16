rule TTP_XOR_QUAD_CurrentVersionRun_0c8d {
  strings:
    $key_0c8d = { 5f e2 [2] 7b ec [2] 50 c0 [2] 7e e2 [2] 6a f9 [2] 65 e3 [2] 7b fe [2] 79 ff [2] 62 f9 [2] 7e fe [2] 62 d1 }

  condition:
    any of them
}