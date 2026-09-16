rule TTP_XOR_QUAD_CurrentVersionRun_4a3e {
  strings:
    $key_4a3e = { 19 51 [2] 3d 5f [2] 16 73 [2] 38 51 [2] 2c 4a [2] 23 50 [2] 3d 4d [2] 3f 4c [2] 24 4a [2] 38 4d [2] 24 62 }

  condition:
    any of them
}