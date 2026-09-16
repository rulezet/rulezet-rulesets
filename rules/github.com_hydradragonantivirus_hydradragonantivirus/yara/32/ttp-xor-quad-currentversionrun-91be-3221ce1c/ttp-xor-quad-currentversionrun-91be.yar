rule TTP_XOR_QUAD_CurrentVersionRun_91be {
  strings:
    $key_91be = { c2 d1 [2] e6 df [2] cd f3 [2] e3 d1 [2] f7 ca [2] f8 d0 [2] e6 cd [2] e4 cc [2] ff ca [2] e3 cd [2] ff e2 }

  condition:
    any of them
}