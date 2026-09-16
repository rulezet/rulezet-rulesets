rule TTP_XOR_QUAD_CurrentVersionRun_a3e0 {
  strings:
    $key_a3e0 = { f0 8f [2] d4 81 [2] ff ad [2] d1 8f [2] c5 94 [2] ca 8e [2] d4 93 [2] d6 92 [2] cd 94 [2] d1 93 [2] cd bc }

  condition:
    any of them
}