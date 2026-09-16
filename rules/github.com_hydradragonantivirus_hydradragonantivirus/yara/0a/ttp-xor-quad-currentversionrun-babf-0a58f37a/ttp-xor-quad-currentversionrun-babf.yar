rule TTP_XOR_QUAD_CurrentVersionRun_babf {
  strings:
    $key_babf = { e9 d0 [2] cd de [2] e6 f2 [2] c8 d0 [2] dc cb [2] d3 d1 [2] cd cc [2] cf cd [2] d4 cb [2] c8 cc [2] d4 e3 }

  condition:
    any of them
}