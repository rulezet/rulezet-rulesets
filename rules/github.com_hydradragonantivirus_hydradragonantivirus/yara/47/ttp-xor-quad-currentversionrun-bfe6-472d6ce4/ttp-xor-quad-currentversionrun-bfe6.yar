rule TTP_XOR_QUAD_CurrentVersionRun_bfe6 {
  strings:
    $key_bfe6 = { ec 89 [2] c8 87 [2] e3 ab [2] cd 89 [2] d9 92 [2] d6 88 [2] c8 95 [2] ca 94 [2] d1 92 [2] cd 95 [2] d1 ba }

  condition:
    any of them
}