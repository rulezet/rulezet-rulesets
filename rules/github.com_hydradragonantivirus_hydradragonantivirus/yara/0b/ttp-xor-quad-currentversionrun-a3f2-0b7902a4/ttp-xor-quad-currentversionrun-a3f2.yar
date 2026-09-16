rule TTP_XOR_QUAD_CurrentVersionRun_a3f2 {
  strings:
    $key_a3f2 = { f0 9d [2] d4 93 [2] ff bf [2] d1 9d [2] c5 86 [2] ca 9c [2] d4 81 [2] d6 80 [2] cd 86 [2] d1 81 [2] cd ae }

  condition:
    any of them
}