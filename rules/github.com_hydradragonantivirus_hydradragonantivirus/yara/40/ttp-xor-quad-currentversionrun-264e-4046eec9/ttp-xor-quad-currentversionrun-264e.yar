rule TTP_XOR_QUAD_CurrentVersionRun_264e {
  strings:
    $key_264e = { 75 21 [2] 51 2f [2] 7a 03 [2] 54 21 [2] 40 3a [2] 4f 20 [2] 51 3d [2] 53 3c [2] 48 3a [2] 54 3d [2] 48 12 }

  condition:
    any of them
}