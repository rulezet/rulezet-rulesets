rule TTP_XOR_QUAD_CurrentVersionRun_c9c2 {
  strings:
    $key_c9c2 = { 9a ad [2] be a3 [2] 95 8f [2] bb ad [2] af b6 [2] a0 ac [2] be b1 [2] bc b0 [2] a7 b6 [2] bb b1 [2] a7 9e }

  condition:
    any of them
}