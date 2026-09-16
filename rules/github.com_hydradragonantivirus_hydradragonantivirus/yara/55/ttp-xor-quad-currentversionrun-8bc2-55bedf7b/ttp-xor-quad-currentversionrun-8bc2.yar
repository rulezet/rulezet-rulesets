rule TTP_XOR_QUAD_CurrentVersionRun_8bc2 {
  strings:
    $key_8bc2 = { d8 ad [2] fc a3 [2] d7 8f [2] f9 ad [2] ed b6 [2] e2 ac [2] fc b1 [2] fe b0 [2] e5 b6 [2] f9 b1 [2] e5 9e }

  condition:
    any of them
}