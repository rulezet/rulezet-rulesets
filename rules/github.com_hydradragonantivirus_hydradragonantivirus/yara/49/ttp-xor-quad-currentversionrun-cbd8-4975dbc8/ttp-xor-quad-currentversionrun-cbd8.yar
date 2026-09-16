rule TTP_XOR_QUAD_CurrentVersionRun_cbd8 {
  strings:
    $key_cbd8 = { 98 b7 [2] bc b9 [2] 97 95 [2] b9 b7 [2] ad ac [2] a2 b6 [2] bc ab [2] be aa [2] a5 ac [2] b9 ab [2] a5 84 }

  condition:
    any of them
}