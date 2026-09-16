rule TTP_XOR_QUAD_CurrentVersionRun_67ce {
  strings:
    $key_67ce = { 34 a1 [2] 10 af [2] 3b 83 [2] 15 a1 [2] 01 ba [2] 0e a0 [2] 10 bd [2] 12 bc [2] 09 ba [2] 15 bd [2] 09 92 }

  condition:
    any of them
}