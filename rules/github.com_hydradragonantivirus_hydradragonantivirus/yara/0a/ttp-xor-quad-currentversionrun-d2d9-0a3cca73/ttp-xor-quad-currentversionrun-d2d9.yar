rule TTP_XOR_QUAD_CurrentVersionRun_d2d9 {
  strings:
    $key_d2d9 = { 81 b6 [2] a5 b8 [2] 8e 94 [2] a0 b6 [2] b4 ad [2] bb b7 [2] a5 aa [2] a7 ab [2] bc ad [2] a0 aa [2] bc 85 }

  condition:
    any of them
}