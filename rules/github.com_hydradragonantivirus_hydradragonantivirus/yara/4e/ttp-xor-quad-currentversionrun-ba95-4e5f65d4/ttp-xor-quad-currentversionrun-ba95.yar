rule TTP_XOR_QUAD_CurrentVersionRun_ba95 {
  strings:
    $key_ba95 = { e9 fa [2] cd f4 [2] e6 d8 [2] c8 fa [2] dc e1 [2] d3 fb [2] cd e6 [2] cf e7 [2] d4 e1 [2] c8 e6 [2] d4 c9 }

  condition:
    any of them
}