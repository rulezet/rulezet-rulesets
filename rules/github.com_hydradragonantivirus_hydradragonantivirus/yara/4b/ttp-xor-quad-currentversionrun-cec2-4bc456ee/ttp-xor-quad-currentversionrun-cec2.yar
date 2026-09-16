rule TTP_XOR_QUAD_CurrentVersionRun_cec2 {
  strings:
    $key_cec2 = { 9d ad [2] b9 a3 [2] 92 8f [2] bc ad [2] a8 b6 [2] a7 ac [2] b9 b1 [2] bb b0 [2] a0 b6 [2] bc b1 [2] a0 9e }

  condition:
    any of them
}