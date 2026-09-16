rule TTP_XOR_QUAD_CurrentVersionRun_8bc1 {
  strings:
    $key_8bc1 = { d8 ae [2] fc a0 [2] d7 8c [2] f9 ae [2] ed b5 [2] e2 af [2] fc b2 [2] fe b3 [2] e5 b5 [2] f9 b2 [2] e5 9d }

  condition:
    any of them
}