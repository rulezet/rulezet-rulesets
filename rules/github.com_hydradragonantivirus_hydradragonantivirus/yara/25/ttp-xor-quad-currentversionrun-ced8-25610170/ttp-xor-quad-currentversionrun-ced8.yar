rule TTP_XOR_QUAD_CurrentVersionRun_ced8 {
  strings:
    $key_ced8 = { 9d b7 [2] b9 b9 [2] 92 95 [2] bc b7 [2] a8 ac [2] a7 b6 [2] b9 ab [2] bb aa [2] a0 ac [2] bc ab [2] a0 84 }

  condition:
    any of them
}