rule TTP_XOR_QUAD_CurrentVersionRun_4857 {
  strings:
    $key_4857 = { 1b 38 [2] 3f 36 [2] 14 1a [2] 3a 38 [2] 2e 23 [2] 21 39 [2] 3f 24 [2] 3d 25 [2] 26 23 [2] 3a 24 [2] 26 0b }

  condition:
    any of them
}