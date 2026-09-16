rule TTP_XOR_QUAD_CurrentVersionRun_03ce {
  strings:
    $key_03ce = { 50 a1 [2] 74 af [2] 5f 83 [2] 71 a1 [2] 65 ba [2] 6a a0 [2] 74 bd [2] 76 bc [2] 6d ba [2] 71 bd [2] 6d 92 }

  condition:
    any of them
}