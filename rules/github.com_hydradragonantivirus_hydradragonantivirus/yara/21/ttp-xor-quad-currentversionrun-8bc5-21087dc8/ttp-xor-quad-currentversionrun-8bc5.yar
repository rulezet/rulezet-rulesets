rule TTP_XOR_QUAD_CurrentVersionRun_8bc5 {
  strings:
    $key_8bc5 = { d8 aa [2] fc a4 [2] d7 88 [2] f9 aa [2] ed b1 [2] e2 ab [2] fc b6 [2] fe b7 [2] e5 b1 [2] f9 b6 [2] e5 99 }

  condition:
    any of them
}