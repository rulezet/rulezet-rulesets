rule TTP_XOR_QUAD_CurrentVersionRun_c4b5 {
  strings:
    $key_c4b5 = { 97 da [2] b3 d4 [2] 98 f8 [2] b6 da [2] a2 c1 [2] ad db [2] b3 c6 [2] b1 c7 [2] aa c1 [2] b6 c6 [2] aa e9 }

  condition:
    any of them
}