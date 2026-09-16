rule TTP_XOR_QUAD_CurrentVersionRun_35ce {
  strings:
    $key_35ce = { 66 a1 [2] 42 af [2] 69 83 [2] 47 a1 [2] 53 ba [2] 5c a0 [2] 42 bd [2] 40 bc [2] 5b ba [2] 47 bd [2] 5b 92 }

  condition:
    any of them
}