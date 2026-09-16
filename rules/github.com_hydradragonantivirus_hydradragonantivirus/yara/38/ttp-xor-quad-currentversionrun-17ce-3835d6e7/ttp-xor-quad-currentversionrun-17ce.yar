rule TTP_XOR_QUAD_CurrentVersionRun_17ce {
  strings:
    $key_17ce = { 44 a1 [2] 60 af [2] 4b 83 [2] 65 a1 [2] 71 ba [2] 7e a0 [2] 60 bd [2] 62 bc [2] 79 ba [2] 65 bd [2] 79 92 }

  condition:
    any of them
}