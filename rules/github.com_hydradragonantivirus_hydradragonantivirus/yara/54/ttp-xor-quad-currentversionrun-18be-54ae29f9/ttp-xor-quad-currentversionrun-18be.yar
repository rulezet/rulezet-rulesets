rule TTP_XOR_QUAD_CurrentVersionRun_18be {
  strings:
    $key_18be = { 4b d1 [2] 6f df [2] 44 f3 [2] 6a d1 [2] 7e ca [2] 71 d0 [2] 6f cd [2] 6d cc [2] 76 ca [2] 6a cd [2] 76 e2 }

  condition:
    any of them
}