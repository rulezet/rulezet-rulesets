rule TTP_XOR_QUAD_CurrentVersionRun_c4b3 {
  strings:
    $key_c4b3 = { 97 dc [2] b3 d2 [2] 98 fe [2] b6 dc [2] a2 c7 [2] ad dd [2] b3 c0 [2] b1 c1 [2] aa c7 [2] b6 c0 [2] aa ef }

  condition:
    any of them
}