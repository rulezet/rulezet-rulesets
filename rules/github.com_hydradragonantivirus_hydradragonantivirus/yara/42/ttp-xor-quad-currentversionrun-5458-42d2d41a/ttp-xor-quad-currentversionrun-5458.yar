rule TTP_XOR_QUAD_CurrentVersionRun_5458 {
  strings:
    $key_5458 = { 07 37 [2] 23 39 [2] 08 15 [2] 26 37 [2] 32 2c [2] 3d 36 [2] 23 2b [2] 21 2a [2] 3a 2c [2] 26 2b [2] 3a 04 }

  condition:
    any of them
}