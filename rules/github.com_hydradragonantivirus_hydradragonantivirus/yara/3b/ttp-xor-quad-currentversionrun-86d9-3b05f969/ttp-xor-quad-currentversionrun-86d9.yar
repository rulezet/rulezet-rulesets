rule TTP_XOR_QUAD_CurrentVersionRun_86d9 {
  strings:
    $key_86d9 = { d5 b6 [2] f1 b8 [2] da 94 [2] f4 b6 [2] e0 ad [2] ef b7 [2] f1 aa [2] f3 ab [2] e8 ad [2] f4 aa [2] e8 85 }

  condition:
    any of them
}