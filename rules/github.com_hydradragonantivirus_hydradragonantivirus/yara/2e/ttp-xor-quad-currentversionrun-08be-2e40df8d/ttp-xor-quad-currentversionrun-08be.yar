rule TTP_XOR_QUAD_CurrentVersionRun_08be {
  strings:
    $key_08be = { 5b d1 [2] 7f df [2] 54 f3 [2] 7a d1 [2] 6e ca [2] 61 d0 [2] 7f cd [2] 7d cc [2] 66 ca [2] 7a cd [2] 66 e2 }

  condition:
    any of them
}