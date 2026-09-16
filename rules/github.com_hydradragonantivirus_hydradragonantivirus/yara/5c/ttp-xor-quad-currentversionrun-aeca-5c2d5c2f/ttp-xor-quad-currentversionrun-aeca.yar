rule TTP_XOR_QUAD_CurrentVersionRun_aeca {
  strings:
    $key_aeca = { fd a5 [2] d9 ab [2] f2 87 [2] dc a5 [2] c8 be [2] c7 a4 [2] d9 b9 [2] db b8 [2] c0 be [2] dc b9 [2] c0 96 }

  condition:
    any of them
}