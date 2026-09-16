rule TTP_XOR_QUAD_CurrentVersionRun_abe6 {
  strings:
    $key_abe6 = { f8 89 [2] dc 87 [2] f7 ab [2] d9 89 [2] cd 92 [2] c2 88 [2] dc 95 [2] de 94 [2] c5 92 [2] d9 95 [2] c5 ba }

  condition:
    any of them
}