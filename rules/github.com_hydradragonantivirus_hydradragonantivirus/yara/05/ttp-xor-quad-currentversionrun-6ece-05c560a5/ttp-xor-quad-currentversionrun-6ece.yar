rule TTP_XOR_QUAD_CurrentVersionRun_6ece {
  strings:
    $key_6ece = { 3d a1 [2] 19 af [2] 32 83 [2] 1c a1 [2] 08 ba [2] 07 a0 [2] 19 bd [2] 1b bc [2] 00 ba [2] 1c bd [2] 00 92 }

  condition:
    any of them
}