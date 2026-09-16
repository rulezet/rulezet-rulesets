rule TTP_XOR_QUAD_CurrentVersionRun_a3a3 {
  strings:
    $key_a3a3 = { f0 cc [2] d4 c2 [2] ff ee [2] d1 cc [2] c5 d7 [2] ca cd [2] d4 d0 [2] d6 d1 [2] cd d7 [2] d1 d0 [2] cd ff }

  condition:
    any of them
}