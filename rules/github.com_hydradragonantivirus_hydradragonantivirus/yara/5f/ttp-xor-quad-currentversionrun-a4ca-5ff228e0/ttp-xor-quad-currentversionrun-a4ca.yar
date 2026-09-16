rule TTP_XOR_QUAD_CurrentVersionRun_a4ca {
  strings:
    $key_a4ca = { f7 a5 [2] d3 ab [2] f8 87 [2] d6 a5 [2] c2 be [2] cd a4 [2] d3 b9 [2] d1 b8 [2] ca be [2] d6 b9 [2] ca 96 }

  condition:
    any of them
}