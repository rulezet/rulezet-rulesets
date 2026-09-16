rule TTP_XOR_QUAD_CurrentVersionRun_dd8d {
  strings:
    $key_dd8d = { 8e e2 [2] aa ec [2] 81 c0 [2] af e2 [2] bb f9 [2] b4 e3 [2] aa fe [2] a8 ff [2] b3 f9 [2] af fe [2] b3 d1 }

  condition:
    any of them
}