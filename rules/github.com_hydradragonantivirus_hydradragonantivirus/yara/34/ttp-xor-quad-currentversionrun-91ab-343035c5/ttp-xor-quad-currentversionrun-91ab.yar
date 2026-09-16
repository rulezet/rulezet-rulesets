rule TTP_XOR_QUAD_CurrentVersionRun_91ab {
  strings:
    $key_91ab = { c2 c4 [2] e6 ca [2] cd e6 [2] e3 c4 [2] f7 df [2] f8 c5 [2] e6 d8 [2] e4 d9 [2] ff df [2] e3 d8 [2] ff f7 }

  condition:
    any of them
}