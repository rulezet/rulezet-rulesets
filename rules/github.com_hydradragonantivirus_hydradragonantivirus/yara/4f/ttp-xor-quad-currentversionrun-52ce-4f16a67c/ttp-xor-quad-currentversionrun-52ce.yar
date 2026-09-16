rule TTP_XOR_QUAD_CurrentVersionRun_52ce {
  strings:
    $key_52ce = { 01 a1 [2] 25 af [2] 0e 83 [2] 20 a1 [2] 34 ba [2] 3b a0 [2] 25 bd [2] 27 bc [2] 3c ba [2] 20 bd [2] 3c 92 }

  condition:
    any of them
}