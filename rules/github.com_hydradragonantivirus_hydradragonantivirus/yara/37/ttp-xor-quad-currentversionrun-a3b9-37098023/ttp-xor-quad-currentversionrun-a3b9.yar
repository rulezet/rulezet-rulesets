rule TTP_XOR_QUAD_CurrentVersionRun_a3b9 {
  strings:
    $key_a3b9 = { f0 d6 [2] d4 d8 [2] ff f4 [2] d1 d6 [2] c5 cd [2] ca d7 [2] d4 ca [2] d6 cb [2] cd cd [2] d1 ca [2] cd e5 }

  condition:
    any of them
}