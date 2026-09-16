rule TTP_XOR_QUAD_CurrentVersionRun_98c2 {
  strings:
    $key_98c2 = { cb ad [2] ef a3 [2] c4 8f [2] ea ad [2] fe b6 [2] f1 ac [2] ef b1 [2] ed b0 [2] f6 b6 [2] ea b1 [2] f6 9e }

  condition:
    any of them
}