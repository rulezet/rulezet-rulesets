rule TTP_XOR_QUAD_CurrentVersionRun_ec8d {
  strings:
    $key_ec8d = { bf e2 [2] 9b ec [2] b0 c0 [2] 9e e2 [2] 8a f9 [2] 85 e3 [2] 9b fe [2] 99 ff [2] 82 f9 [2] 9e fe [2] 82 d1 }

  condition:
    any of them
}