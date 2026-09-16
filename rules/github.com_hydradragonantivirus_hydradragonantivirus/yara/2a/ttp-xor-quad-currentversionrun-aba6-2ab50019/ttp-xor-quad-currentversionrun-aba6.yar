rule TTP_XOR_QUAD_CurrentVersionRun_aba6 {
  strings:
    $key_aba6 = { f8 c9 [2] dc c7 [2] f7 eb [2] d9 c9 [2] cd d2 [2] c2 c8 [2] dc d5 [2] de d4 [2] c5 d2 [2] d9 d5 [2] c5 fa }

  condition:
    any of them
}