rule TTP_XOR_QUAD_CurrentVersionRun_98c4 {
  strings:
    $key_98c4 = { cb ab [2] ef a5 [2] c4 89 [2] ea ab [2] fe b0 [2] f1 aa [2] ef b7 [2] ed b6 [2] f6 b0 [2] ea b7 [2] f6 98 }

  condition:
    any of them
}