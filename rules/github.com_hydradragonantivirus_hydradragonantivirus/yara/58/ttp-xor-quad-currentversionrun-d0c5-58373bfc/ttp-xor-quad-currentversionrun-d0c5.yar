rule TTP_XOR_QUAD_CurrentVersionRun_d0c5 {
  strings:
    $key_d0c5 = { 83 aa [2] a7 a4 [2] 8c 88 [2] a2 aa [2] b6 b1 [2] b9 ab [2] a7 b6 [2] a5 b7 [2] be b1 [2] a2 b6 [2] be 99 }

  condition:
    any of them
}