rule TTP_XOR_QUAD_CurrentVersionRun_4a68 {
  strings:
    $key_4a68 = { 19 07 [2] 3d 09 [2] 16 25 [2] 38 07 [2] 2c 1c [2] 23 06 [2] 3d 1b [2] 3f 1a [2] 24 1c [2] 38 1b [2] 24 34 }

  condition:
    any of them
}