rule TTP_XOR_QUAD_CurrentVersionRun_51ce {
  strings:
    $key_51ce = { 02 a1 [2] 26 af [2] 0d 83 [2] 23 a1 [2] 37 ba [2] 38 a0 [2] 26 bd [2] 24 bc [2] 3f ba [2] 23 bd [2] 3f 92 }

  condition:
    any of them
}