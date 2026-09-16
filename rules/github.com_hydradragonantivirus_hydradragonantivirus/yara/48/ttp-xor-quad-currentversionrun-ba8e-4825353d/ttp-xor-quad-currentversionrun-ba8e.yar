rule TTP_XOR_QUAD_CurrentVersionRun_ba8e {
  strings:
    $key_ba8e = { e9 e1 [2] cd ef [2] e6 c3 [2] c8 e1 [2] dc fa [2] d3 e0 [2] cd fd [2] cf fc [2] d4 fa [2] c8 fd [2] d4 d2 }

  condition:
    any of them
}