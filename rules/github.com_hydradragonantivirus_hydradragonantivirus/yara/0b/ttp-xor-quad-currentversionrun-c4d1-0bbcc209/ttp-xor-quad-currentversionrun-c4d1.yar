rule TTP_XOR_QUAD_CurrentVersionRun_c4d1 {
  strings:
    $key_c4d1 = { 97 be [2] b3 b0 [2] 98 9c [2] b6 be [2] a2 a5 [2] ad bf [2] b3 a2 [2] b1 a3 [2] aa a5 [2] b6 a2 [2] aa 8d }

  condition:
    any of them
}