rule TTP_XOR_QUAD_CurrentVersionRun_58be {
  strings:
    $key_58be = { 0b d1 [2] 2f df [2] 04 f3 [2] 2a d1 [2] 3e ca [2] 31 d0 [2] 2f cd [2] 2d cc [2] 36 ca [2] 2a cd [2] 36 e2 }

  condition:
    any of them
}