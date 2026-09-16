rule TTP_XOR_QUAD_CurrentVersionRun_8198 {
  strings:
    $key_8198 = { d2 f7 [2] f6 f9 [2] dd d5 [2] f3 f7 [2] e7 ec [2] e8 f6 [2] f6 eb [2] f4 ea [2] ef ec [2] f3 eb [2] ef c4 }

  condition:
    any of them
}