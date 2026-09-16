rule TTP_XOR_QUAD_CurrentVersionRun_91a2 {
  strings:
    $key_91a2 = { c2 cd [2] e6 c3 [2] cd ef [2] e3 cd [2] f7 d6 [2] f8 cc [2] e6 d1 [2] e4 d0 [2] ff d6 [2] e3 d1 [2] ff fe }

  condition:
    any of them
}