rule TTP_XOR_QUAD_CurrentVersionRun_c2b3 {
  strings:
    $key_c2b3 = { 91 dc [2] b5 d2 [2] 9e fe [2] b0 dc [2] a4 c7 [2] ab dd [2] b5 c0 [2] b7 c1 [2] ac c7 [2] b0 c0 [2] ac ef }

  condition:
    any of them
}