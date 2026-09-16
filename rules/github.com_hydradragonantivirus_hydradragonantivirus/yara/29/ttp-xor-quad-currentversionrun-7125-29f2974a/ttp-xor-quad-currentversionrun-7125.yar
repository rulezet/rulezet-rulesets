rule TTP_XOR_QUAD_CurrentVersionRun_7125 {
  strings:
    $key_7125 = { 22 4a [2] 06 44 [2] 2d 68 [2] 03 4a [2] 17 51 [2] 18 4b [2] 06 56 [2] 04 57 [2] 1f 51 [2] 03 56 [2] 1f 79 }

  condition:
    any of them
}