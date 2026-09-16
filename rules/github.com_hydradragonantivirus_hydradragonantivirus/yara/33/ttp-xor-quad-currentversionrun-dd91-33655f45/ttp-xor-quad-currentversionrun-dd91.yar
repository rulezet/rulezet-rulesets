rule TTP_XOR_QUAD_CurrentVersionRun_dd91 {
  strings:
    $key_dd91 = { 8e fe [2] aa f0 [2] 81 dc [2] af fe [2] bb e5 [2] b4 ff [2] aa e2 [2] a8 e3 [2] b3 e5 [2] af e2 [2] b3 cd }

  condition:
    any of them
}