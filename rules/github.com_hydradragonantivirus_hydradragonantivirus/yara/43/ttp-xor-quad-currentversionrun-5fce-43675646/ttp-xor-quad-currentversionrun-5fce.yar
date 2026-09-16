rule TTP_XOR_QUAD_CurrentVersionRun_5fce {
  strings:
    $key_5fce = { 0c a1 [2] 28 af [2] 03 83 [2] 2d a1 [2] 39 ba [2] 36 a0 [2] 28 bd [2] 2a bc [2] 31 ba [2] 2d bd [2] 31 92 }

  condition:
    any of them
}