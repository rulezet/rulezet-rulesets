rule TTP_XOR_QUAD_CurrentVersionRun_464b {
  strings:
    $key_464b = { 15 24 [2] 31 2a [2] 1a 06 [2] 34 24 [2] 20 3f [2] 2f 25 [2] 31 38 [2] 33 39 [2] 28 3f [2] 34 38 [2] 28 17 }

  condition:
    any of them
}