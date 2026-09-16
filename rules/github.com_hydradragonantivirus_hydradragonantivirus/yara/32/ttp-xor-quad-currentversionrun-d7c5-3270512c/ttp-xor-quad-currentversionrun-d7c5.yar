rule TTP_XOR_QUAD_CurrentVersionRun_d7c5 {
  strings:
    $key_d7c5 = { 84 aa [2] a0 a4 [2] 8b 88 [2] a5 aa [2] b1 b1 [2] be ab [2] a0 b6 [2] a2 b7 [2] b9 b1 [2] a5 b6 [2] b9 99 }

  condition:
    any of them
}