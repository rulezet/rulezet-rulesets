rule TTP_XOR_QUAD_CurrentVersionRun_754e {
  strings:
    $key_754e = { 26 21 [2] 02 2f [2] 29 03 [2] 07 21 [2] 13 3a [2] 1c 20 [2] 02 3d [2] 00 3c [2] 1b 3a [2] 07 3d [2] 1b 12 }

  condition:
    any of them
}