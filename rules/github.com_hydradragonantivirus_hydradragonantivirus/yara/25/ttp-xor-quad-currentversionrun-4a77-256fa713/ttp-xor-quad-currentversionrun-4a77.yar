rule TTP_XOR_QUAD_CurrentVersionRun_4a77 {
  strings:
    $key_4a77 = { 19 18 [2] 3d 16 [2] 16 3a [2] 38 18 [2] 2c 03 [2] 23 19 [2] 3d 04 [2] 3f 05 [2] 24 03 [2] 38 04 [2] 24 2b }

  condition:
    any of them
}