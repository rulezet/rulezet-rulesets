rule TTP_XOR_QUAD_CurrentVersionRun_8bc3 {
  strings:
    $key_8bc3 = { d8 ac [2] fc a2 [2] d7 8e [2] f9 ac [2] ed b7 [2] e2 ad [2] fc b0 [2] fe b1 [2] e5 b7 [2] f9 b0 [2] e5 9f }

  condition:
    any of them
}