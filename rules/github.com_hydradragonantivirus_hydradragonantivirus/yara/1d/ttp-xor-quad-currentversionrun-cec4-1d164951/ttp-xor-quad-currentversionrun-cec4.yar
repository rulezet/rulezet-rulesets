rule TTP_XOR_QUAD_CurrentVersionRun_cec4 {
  strings:
    $key_cec4 = { 9d ab [2] b9 a5 [2] 92 89 [2] bc ab [2] a8 b0 [2] a7 aa [2] b9 b7 [2] bb b6 [2] a0 b0 [2] bc b7 [2] a0 98 }

  condition:
    any of them
}