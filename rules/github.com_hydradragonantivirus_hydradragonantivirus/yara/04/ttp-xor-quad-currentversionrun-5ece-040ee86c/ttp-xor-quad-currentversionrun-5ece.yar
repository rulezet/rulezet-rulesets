rule TTP_XOR_QUAD_CurrentVersionRun_5ece {
  strings:
    $key_5ece = { 0d a1 [2] 29 af [2] 02 83 [2] 2c a1 [2] 38 ba [2] 37 a0 [2] 29 bd [2] 2b bc [2] 30 ba [2] 2c bd [2] 30 92 }

  condition:
    any of them
}