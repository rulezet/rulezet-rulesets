rule TTP_XOR_QUAD_CurrentVersionRun_aba3 {
  strings:
    $key_aba3 = { f8 cc [2] dc c2 [2] f7 ee [2] d9 cc [2] cd d7 [2] c2 cd [2] dc d0 [2] de d1 [2] c5 d7 [2] d9 d0 [2] c5 ff }

  condition:
    any of them
}