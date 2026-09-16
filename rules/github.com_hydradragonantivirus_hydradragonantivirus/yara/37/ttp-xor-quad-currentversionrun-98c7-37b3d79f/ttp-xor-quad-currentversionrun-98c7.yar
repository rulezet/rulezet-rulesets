rule TTP_XOR_QUAD_CurrentVersionRun_98c7 {
  strings:
    $key_98c7 = { cb a8 [2] ef a6 [2] c4 8a [2] ea a8 [2] fe b3 [2] f1 a9 [2] ef b4 [2] ed b5 [2] f6 b3 [2] ea b4 [2] f6 9b }

  condition:
    any of them
}