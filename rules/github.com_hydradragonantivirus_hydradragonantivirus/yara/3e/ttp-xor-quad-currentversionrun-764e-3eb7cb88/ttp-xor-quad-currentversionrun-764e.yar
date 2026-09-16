rule TTP_XOR_QUAD_CurrentVersionRun_764e {
  strings:
    $key_764e = { 25 21 [2] 01 2f [2] 2a 03 [2] 04 21 [2] 10 3a [2] 1f 20 [2] 01 3d [2] 03 3c [2] 18 3a [2] 04 3d [2] 18 12 }

  condition:
    any of them
}