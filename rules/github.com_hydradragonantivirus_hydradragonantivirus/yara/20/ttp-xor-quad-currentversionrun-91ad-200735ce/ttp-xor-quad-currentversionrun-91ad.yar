rule TTP_XOR_QUAD_CurrentVersionRun_91ad {
  strings:
    $key_91ad = { c2 c2 [2] e6 cc [2] cd e0 [2] e3 c2 [2] f7 d9 [2] f8 c3 [2] e6 de [2] e4 df [2] ff d9 [2] e3 de [2] ff f1 }

  condition:
    any of them
}