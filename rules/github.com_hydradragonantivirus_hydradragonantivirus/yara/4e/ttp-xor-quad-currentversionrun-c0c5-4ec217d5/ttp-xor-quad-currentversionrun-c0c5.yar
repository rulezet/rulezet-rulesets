rule TTP_XOR_QUAD_CurrentVersionRun_c0c5 {
  strings:
    $key_c0c5 = { 93 aa [2] b7 a4 [2] 9c 88 [2] b2 aa [2] a6 b1 [2] a9 ab [2] b7 b6 [2] b5 b7 [2] ae b1 [2] b2 b6 [2] ae 99 }

  condition:
    any of them
}