rule TTP_XOR_QUAD_CurrentVersionRun_8bc4 {
  strings:
    $key_8bc4 = { d8 ab [2] fc a5 [2] d7 89 [2] f9 ab [2] ed b0 [2] e2 aa [2] fc b7 [2] fe b6 [2] e5 b0 [2] f9 b7 [2] e5 98 }

  condition:
    any of them
}