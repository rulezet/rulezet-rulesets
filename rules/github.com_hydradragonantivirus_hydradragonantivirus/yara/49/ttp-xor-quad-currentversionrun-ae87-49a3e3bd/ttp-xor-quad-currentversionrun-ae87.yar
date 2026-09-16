rule TTP_XOR_QUAD_CurrentVersionRun_ae87 {
  strings:
    $key_ae87 = { fd e8 [2] d9 e6 [2] f2 ca [2] dc e8 [2] c8 f3 [2] c7 e9 [2] d9 f4 [2] db f5 [2] c0 f3 [2] dc f4 [2] c0 db }

  condition:
    any of them
}