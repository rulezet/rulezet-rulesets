rule TTP_XOR_QUAD_CurrentVersionRun_78be {
  strings:
    $key_78be = { 2b d1 [2] 0f df [2] 24 f3 [2] 0a d1 [2] 1e ca [2] 11 d0 [2] 0f cd [2] 0d cc [2] 16 ca [2] 0a cd [2] 16 e2 }

  condition:
    any of them
}