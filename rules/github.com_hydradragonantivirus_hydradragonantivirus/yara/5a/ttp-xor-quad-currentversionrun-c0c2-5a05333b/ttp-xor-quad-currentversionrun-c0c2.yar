rule TTP_XOR_QUAD_CurrentVersionRun_c0c2 {
  strings:
    $key_c0c2 = { 93 ad [2] b7 a3 [2] 9c 8f [2] b2 ad [2] a6 b6 [2] a9 ac [2] b7 b1 [2] b5 b0 [2] ae b6 [2] b2 b1 [2] ae 9e }

  condition:
    any of them
}