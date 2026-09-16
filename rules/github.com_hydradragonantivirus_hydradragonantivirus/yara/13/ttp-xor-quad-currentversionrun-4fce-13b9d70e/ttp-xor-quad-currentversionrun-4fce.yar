rule TTP_XOR_QUAD_CurrentVersionRun_4fce {
  strings:
    $key_4fce = { 1c a1 [2] 38 af [2] 13 83 [2] 3d a1 [2] 29 ba [2] 26 a0 [2] 38 bd [2] 3a bc [2] 21 ba [2] 3d bd [2] 21 92 }

  condition:
    any of them
}