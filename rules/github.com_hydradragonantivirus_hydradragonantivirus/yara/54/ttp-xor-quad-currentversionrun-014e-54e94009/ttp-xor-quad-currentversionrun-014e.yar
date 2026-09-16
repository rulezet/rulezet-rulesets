rule TTP_XOR_QUAD_CurrentVersionRun_014e {
  strings:
    $key_014e = { 52 21 [2] 76 2f [2] 5d 03 [2] 73 21 [2] 67 3a [2] 68 20 [2] 76 3d [2] 74 3c [2] 6f 3a [2] 73 3d [2] 6f 12 }

  condition:
    any of them
}