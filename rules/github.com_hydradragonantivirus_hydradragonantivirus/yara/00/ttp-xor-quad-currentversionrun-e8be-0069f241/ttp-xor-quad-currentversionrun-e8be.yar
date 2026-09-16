rule TTP_XOR_QUAD_CurrentVersionRun_e8be {
  strings:
    $key_e8be = { bb d1 [2] 9f df [2] b4 f3 [2] 9a d1 [2] 8e ca [2] 81 d0 [2] 9f cd [2] 9d cc [2] 86 ca [2] 9a cd [2] 86 e2 }

  condition:
    any of them
}