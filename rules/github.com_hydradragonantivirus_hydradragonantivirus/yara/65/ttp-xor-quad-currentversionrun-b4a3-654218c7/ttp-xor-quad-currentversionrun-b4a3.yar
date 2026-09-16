rule TTP_XOR_QUAD_CurrentVersionRun_b4a3 {
  strings:
    $key_b4a3 = { e7 cc [2] c3 c2 [2] e8 ee [2] c6 cc [2] d2 d7 [2] dd cd [2] c3 d0 [2] c1 d1 [2] da d7 [2] c6 d0 [2] da ff }

  condition:
    any of them
}