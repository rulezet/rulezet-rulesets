rule TTP_XOR_QUAD_CurrentVersionRun_1368 {
  strings:
    $key_1368 = { 40 07 [2] 64 09 [2] 4f 25 [2] 61 07 [2] 75 1c [2] 7a 06 [2] 64 1b [2] 66 1a [2] 7d 1c [2] 61 1b [2] 7d 34 }

  condition:
    any of them
}