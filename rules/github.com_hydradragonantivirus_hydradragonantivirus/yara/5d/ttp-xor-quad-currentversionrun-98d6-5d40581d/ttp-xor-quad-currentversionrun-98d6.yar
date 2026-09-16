rule TTP_XOR_QUAD_CurrentVersionRun_98d6 {
  strings:
    $key_98d6 = { cb b9 [2] ef b7 [2] c4 9b [2] ea b9 [2] fe a2 [2] f1 b8 [2] ef a5 [2] ed a4 [2] f6 a2 [2] ea a5 [2] f6 8a }

  condition:
    any of them
}