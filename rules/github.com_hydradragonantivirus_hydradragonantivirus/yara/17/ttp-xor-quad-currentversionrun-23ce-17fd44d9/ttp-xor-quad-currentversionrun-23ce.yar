rule TTP_XOR_QUAD_CurrentVersionRun_23ce {
  strings:
    $key_23ce = { 70 a1 [2] 54 af [2] 7f 83 [2] 51 a1 [2] 45 ba [2] 4a a0 [2] 54 bd [2] 56 bc [2] 4d ba [2] 51 bd [2] 4d 92 }

  condition:
    any of them
}