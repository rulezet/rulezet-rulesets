rule TTP_XOR_QUAD_CurrentVersionRun_d054 {
  strings:
    $key_d054 = { 83 3b [2] a7 35 [2] 8c 19 [2] a2 3b [2] b6 20 [2] b9 3a [2] a7 27 [2] a5 26 [2] be 20 [2] a2 27 [2] be 08 }

  condition:
    any of them
}