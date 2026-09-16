rule TTP_XOR_QUAD_CurrentVersionRun_27ce {
  strings:
    $key_27ce = { 74 a1 [2] 50 af [2] 7b 83 [2] 55 a1 [2] 41 ba [2] 4e a0 [2] 50 bd [2] 52 bc [2] 49 ba [2] 55 bd [2] 49 92 }

  condition:
    any of them
}