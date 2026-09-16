rule TTP_XOR_QUAD_CurrentVersionRun_34ce {
  strings:
    $key_34ce = { 67 a1 [2] 43 af [2] 68 83 [2] 46 a1 [2] 52 ba [2] 5d a0 [2] 43 bd [2] 41 bc [2] 5a ba [2] 46 bd [2] 5a 92 }

  condition:
    any of them
}