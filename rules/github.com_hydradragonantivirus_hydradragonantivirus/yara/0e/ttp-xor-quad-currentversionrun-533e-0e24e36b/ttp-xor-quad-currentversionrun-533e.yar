rule TTP_XOR_QUAD_CurrentVersionRun_533e {
  strings:
    $key_533e = { 00 51 [2] 24 5f [2] 0f 73 [2] 21 51 [2] 35 4a [2] 3a 50 [2] 24 4d [2] 26 4c [2] 3d 4a [2] 21 4d [2] 3d 62 }

  condition:
    any of them
}