rule TTP_XOR_QUAD_CurrentVersionRun_d0d9 {
  strings:
    $key_d0d9 = { 83 b6 [2] a7 b8 [2] 8c 94 [2] a2 b6 [2] b6 ad [2] b9 b7 [2] a7 aa [2] a5 ab [2] be ad [2] a2 aa [2] be 85 }

  condition:
    any of them
}