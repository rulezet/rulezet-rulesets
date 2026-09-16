rule TTP_XOR_QUAD_CurrentVersionRun_aec1 {
  strings:
    $key_aec1 = { fd ae [2] d9 a0 [2] f2 8c [2] dc ae [2] c8 b5 [2] c7 af [2] d9 b2 [2] db b3 [2] c0 b5 [2] dc b2 [2] c0 9d }

  condition:
    any of them
}