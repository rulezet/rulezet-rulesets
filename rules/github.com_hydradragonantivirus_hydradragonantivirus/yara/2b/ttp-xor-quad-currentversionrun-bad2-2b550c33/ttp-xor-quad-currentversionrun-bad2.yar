rule TTP_XOR_QUAD_CurrentVersionRun_bad2 {
  strings:
    $key_bad2 = { e9 bd [2] cd b3 [2] e6 9f [2] c8 bd [2] dc a6 [2] d3 bc [2] cd a1 [2] cf a0 [2] d4 a6 [2] c8 a1 [2] d4 8e }

  condition:
    any of them
}