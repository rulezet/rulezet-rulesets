rule TTP_XOR_QUAD_CurrentVersionRun_c6c5 {
  strings:
    $key_c6c5 = { 95 aa [2] b1 a4 [2] 9a 88 [2] b4 aa [2] a0 b1 [2] af ab [2] b1 b6 [2] b3 b7 [2] a8 b1 [2] b4 b6 [2] a8 99 }

  condition:
    any of them
}