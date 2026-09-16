rule TTP_XOR_QUAD_CurrentVersionRun_cc9a {
  strings:
    $key_cc9a = { 9f f5 [2] bb fb [2] 90 d7 [2] be f5 [2] aa ee [2] a5 f4 [2] bb e9 [2] b9 e8 [2] a2 ee [2] be e9 [2] a2 c6 }

  condition:
    any of them
}