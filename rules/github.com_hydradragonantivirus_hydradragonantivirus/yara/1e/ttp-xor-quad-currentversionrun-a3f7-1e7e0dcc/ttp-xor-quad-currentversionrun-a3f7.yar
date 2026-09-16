rule TTP_XOR_QUAD_CurrentVersionRun_a3f7 {
  strings:
    $key_a3f7 = { f0 98 [2] d4 96 [2] ff ba [2] d1 98 [2] c5 83 [2] ca 99 [2] d4 84 [2] d6 85 [2] cd 83 [2] d1 84 [2] cd ab }

  condition:
    any of them
}