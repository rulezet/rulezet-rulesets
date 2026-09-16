rule TTP_XOR_QUAD_CurrentVersionRun_ae96 {
  strings:
    $key_ae96 = { fd f9 [2] d9 f7 [2] f2 db [2] dc f9 [2] c8 e2 [2] c7 f8 [2] d9 e5 [2] db e4 [2] c0 e2 [2] dc e5 [2] c0 ca }

  condition:
    any of them
}