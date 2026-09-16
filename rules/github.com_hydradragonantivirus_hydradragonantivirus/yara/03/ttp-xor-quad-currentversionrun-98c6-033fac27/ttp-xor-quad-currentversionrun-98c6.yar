rule TTP_XOR_QUAD_CurrentVersionRun_98c6 {
  strings:
    $key_98c6 = { cb a9 [2] ef a7 [2] c4 8b [2] ea a9 [2] fe b2 [2] f1 a8 [2] ef b5 [2] ed b4 [2] f6 b2 [2] ea b5 [2] f6 9a }

  condition:
    any of them
}