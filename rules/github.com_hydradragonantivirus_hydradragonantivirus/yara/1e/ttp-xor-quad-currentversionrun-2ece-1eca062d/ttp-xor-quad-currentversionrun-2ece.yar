rule TTP_XOR_QUAD_CurrentVersionRun_2ece {
  strings:
    $key_2ece = { 7d a1 [2] 59 af [2] 72 83 [2] 5c a1 [2] 48 ba [2] 47 a0 [2] 59 bd [2] 5b bc [2] 40 ba [2] 5c bd [2] 40 92 }

  condition:
    any of them
}