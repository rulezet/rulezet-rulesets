rule TTP_XOR_QUAD_CurrentVersionRun_364e {
  strings:
    $key_364e = { 65 21 [2] 41 2f [2] 6a 03 [2] 44 21 [2] 50 3a [2] 5f 20 [2] 41 3d [2] 43 3c [2] 58 3a [2] 44 3d [2] 58 12 }

  condition:
    any of them
}