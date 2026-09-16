rule TTP_XOR_QUAD_CurrentVersionRun_abe0 {
  strings:
    $key_abe0 = { f8 8f [2] dc 81 [2] f7 ad [2] d9 8f [2] cd 94 [2] c2 8e [2] dc 93 [2] de 92 [2] c5 94 [2] d9 93 [2] c5 bc }

  condition:
    any of them
}