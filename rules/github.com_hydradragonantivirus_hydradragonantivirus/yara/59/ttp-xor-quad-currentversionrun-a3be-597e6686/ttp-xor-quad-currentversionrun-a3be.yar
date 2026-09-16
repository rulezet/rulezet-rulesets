rule TTP_XOR_QUAD_CurrentVersionRun_a3be {
  strings:
    $key_a3be = { f0 d1 [2] d4 df [2] ff f3 [2] d1 d1 [2] c5 ca [2] ca d0 [2] d4 cd [2] d6 cc [2] cd ca [2] d1 cd [2] cd e2 }

  condition:
    any of them
}