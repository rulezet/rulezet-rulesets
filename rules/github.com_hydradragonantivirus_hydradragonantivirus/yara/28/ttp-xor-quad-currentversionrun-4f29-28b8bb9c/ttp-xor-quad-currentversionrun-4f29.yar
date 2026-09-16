rule TTP_XOR_QUAD_CurrentVersionRun_4f29 {
  strings:
    $key_4f29 = { 1c 46 [2] 38 48 [2] 13 64 [2] 3d 46 [2] 29 5d [2] 26 47 [2] 38 5a [2] 3a 5b [2] 21 5d [2] 3d 5a [2] 21 75 }

  condition:
    any of them
}