rule TTP_XOR_QUAD_CurrentVersionRun_43ce {
  strings:
    $key_43ce = { 10 a1 [2] 34 af [2] 1f 83 [2] 31 a1 [2] 25 ba [2] 2a a0 [2] 34 bd [2] 36 bc [2] 2d ba [2] 31 bd [2] 2d 92 }

  condition:
    any of them
}