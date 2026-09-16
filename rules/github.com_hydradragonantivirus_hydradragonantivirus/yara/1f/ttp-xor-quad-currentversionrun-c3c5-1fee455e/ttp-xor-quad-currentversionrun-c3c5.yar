rule TTP_XOR_QUAD_CurrentVersionRun_c3c5 {
  strings:
    $key_c3c5 = { 90 aa [2] b4 a4 [2] 9f 88 [2] b1 aa [2] a5 b1 [2] aa ab [2] b4 b6 [2] b6 b7 [2] ad b1 [2] b1 b6 [2] ad 99 }

  condition:
    any of them
}