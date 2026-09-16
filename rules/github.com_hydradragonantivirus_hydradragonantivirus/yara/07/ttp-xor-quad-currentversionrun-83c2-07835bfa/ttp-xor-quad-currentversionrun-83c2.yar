rule TTP_XOR_QUAD_CurrentVersionRun_83c2 {
  strings:
    $key_83c2 = { d0 ad [2] f4 a3 [2] df 8f [2] f1 ad [2] e5 b6 [2] ea ac [2] f4 b1 [2] f6 b0 [2] ed b6 [2] f1 b1 [2] ed 9e }

  condition:
    any of them
}