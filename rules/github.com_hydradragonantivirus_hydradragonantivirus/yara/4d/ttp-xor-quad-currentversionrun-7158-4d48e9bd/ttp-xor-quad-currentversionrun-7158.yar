rule TTP_XOR_QUAD_CurrentVersionRun_7158 {
  strings:
    $key_7158 = { 22 37 [2] 06 39 [2] 2d 15 [2] 03 37 [2] 17 2c [2] 18 36 [2] 06 2b [2] 04 2a [2] 1f 2c [2] 03 2b [2] 1f 04 }

  condition:
    any of them
}