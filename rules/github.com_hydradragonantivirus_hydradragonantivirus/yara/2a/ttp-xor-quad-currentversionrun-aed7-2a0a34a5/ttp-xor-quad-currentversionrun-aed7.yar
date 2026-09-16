rule TTP_XOR_QUAD_CurrentVersionRun_aed7 {
  strings:
    $key_aed7 = { fd b8 [2] d9 b6 [2] f2 9a [2] dc b8 [2] c8 a3 [2] c7 b9 [2] d9 a4 [2] db a5 [2] c0 a3 [2] dc a4 [2] c0 8b }

  condition:
    any of them
}