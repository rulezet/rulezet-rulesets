rule TTP_XOR_QUAD_CurrentVersionRun_3ece {
  strings:
    $key_3ece = { 6d a1 [2] 49 af [2] 62 83 [2] 4c a1 [2] 58 ba [2] 57 a0 [2] 49 bd [2] 4b bc [2] 50 ba [2] 4c bd [2] 50 92 }

  condition:
    any of them
}