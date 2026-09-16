rule TTP_XOR_QUAD_CurrentVersionRun_cc9b {
  strings:
    $key_cc9b = { 9f f4 [2] bb fa [2] 90 d6 [2] be f4 [2] aa ef [2] a5 f5 [2] bb e8 [2] b9 e9 [2] a2 ef [2] be e8 [2] a2 c7 }

  condition:
    any of them
}