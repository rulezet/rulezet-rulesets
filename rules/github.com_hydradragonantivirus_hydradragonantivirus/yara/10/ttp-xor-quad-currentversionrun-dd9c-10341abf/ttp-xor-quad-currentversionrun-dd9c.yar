rule TTP_XOR_QUAD_CurrentVersionRun_dd9c {
  strings:
    $key_dd9c = { 8e f3 [2] aa fd [2] 81 d1 [2] af f3 [2] bb e8 [2] b4 f2 [2] aa ef [2] a8 ee [2] b3 e8 [2] af ef [2] b3 c0 }

  condition:
    any of them
}