rule TTP_XOR_QUAD_CurrentVersionRun_532e {
  strings:
    $key_532e = { 00 41 [2] 24 4f [2] 0f 63 [2] 21 41 [2] 35 5a [2] 3a 40 [2] 24 5d [2] 26 5c [2] 3d 5a [2] 21 5d [2] 3d 72 }

  condition:
    any of them
}