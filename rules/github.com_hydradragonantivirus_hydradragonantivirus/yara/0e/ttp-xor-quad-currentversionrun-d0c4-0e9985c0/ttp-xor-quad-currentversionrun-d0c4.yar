rule TTP_XOR_QUAD_CurrentVersionRun_d0c4 {
  strings:
    $key_d0c4 = { 83 ab [2] a7 a5 [2] 8c 89 [2] a2 ab [2] b6 b0 [2] b9 aa [2] a7 b7 [2] a5 b6 [2] be b0 [2] a2 b7 [2] be 98 }

  condition:
    any of them
}