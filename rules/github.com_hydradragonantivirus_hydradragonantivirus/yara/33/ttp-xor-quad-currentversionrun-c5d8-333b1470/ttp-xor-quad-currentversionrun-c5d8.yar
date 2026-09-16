rule TTP_XOR_QUAD_CurrentVersionRun_c5d8 {
  strings:
    $key_c5d8 = { 96 b7 [2] b2 b9 [2] 99 95 [2] b7 b7 [2] a3 ac [2] ac b6 [2] b2 ab [2] b0 aa [2] ab ac [2] b7 ab [2] ab 84 }

  condition:
    any of them
}