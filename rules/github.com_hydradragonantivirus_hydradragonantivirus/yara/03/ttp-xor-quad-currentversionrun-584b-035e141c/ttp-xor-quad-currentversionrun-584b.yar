rule TTP_XOR_QUAD_CurrentVersionRun_584b {
  strings:
    $key_584b = { 0b 24 [2] 2f 2a [2] 04 06 [2] 2a 24 [2] 3e 3f [2] 31 25 [2] 2f 38 [2] 2d 39 [2] 36 3f [2] 2a 38 [2] 36 17 }

  condition:
    any of them
}