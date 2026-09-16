rule TTP_XOR_QUAD_CurrentVersionRun_2fce {
  strings:
    $key_2fce = { 7c a1 [2] 58 af [2] 73 83 [2] 5d a1 [2] 49 ba [2] 46 a0 [2] 58 bd [2] 5a bc [2] 41 ba [2] 5d bd [2] 41 92 }

  condition:
    any of them
}