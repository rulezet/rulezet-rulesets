rule TTP_XOR_QUAD_CurrentVersionRun_d7d9 {
  strings:
    $key_d7d9 = { 84 b6 [2] a0 b8 [2] 8b 94 [2] a5 b6 [2] b1 ad [2] be b7 [2] a0 aa [2] a2 ab [2] b9 ad [2] a5 aa [2] b9 85 }

  condition:
    any of them
}