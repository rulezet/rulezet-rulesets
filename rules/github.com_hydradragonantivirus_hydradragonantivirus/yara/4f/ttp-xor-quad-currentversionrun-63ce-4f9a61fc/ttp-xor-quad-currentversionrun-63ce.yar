rule TTP_XOR_QUAD_CurrentVersionRun_63ce {
  strings:
    $key_63ce = { 30 a1 [2] 14 af [2] 3f 83 [2] 11 a1 [2] 05 ba [2] 0a a0 [2] 14 bd [2] 16 bc [2] 0d ba [2] 11 bd [2] 0d 92 }

  condition:
    any of them
}