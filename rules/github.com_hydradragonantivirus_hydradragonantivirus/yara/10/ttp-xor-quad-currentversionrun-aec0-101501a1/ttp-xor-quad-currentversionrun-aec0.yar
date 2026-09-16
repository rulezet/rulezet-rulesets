rule TTP_XOR_QUAD_CurrentVersionRun_aec0 {
  strings:
    $key_aec0 = { fd af [2] d9 a1 [2] f2 8d [2] dc af [2] c8 b4 [2] c7 ae [2] d9 b3 [2] db b2 [2] c0 b4 [2] dc b3 [2] c0 9c }

  condition:
    any of them
}