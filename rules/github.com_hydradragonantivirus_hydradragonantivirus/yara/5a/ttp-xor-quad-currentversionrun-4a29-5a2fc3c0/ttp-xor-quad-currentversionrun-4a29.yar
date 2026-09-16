rule TTP_XOR_QUAD_CurrentVersionRun_4a29 {
  strings:
    $key_4a29 = { 19 46 [2] 3d 48 [2] 16 64 [2] 38 46 [2] 2c 5d [2] 23 47 [2] 3d 5a [2] 3f 5b [2] 24 5d [2] 38 5a [2] 24 75 }

  condition:
    any of them
}