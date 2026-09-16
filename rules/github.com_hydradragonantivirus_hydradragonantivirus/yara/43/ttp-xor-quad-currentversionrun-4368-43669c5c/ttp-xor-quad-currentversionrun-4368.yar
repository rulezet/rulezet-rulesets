rule TTP_XOR_QUAD_CurrentVersionRun_4368 {
  strings:
    $key_4368 = { 10 07 [2] 34 09 [2] 1f 25 [2] 31 07 [2] 25 1c [2] 2a 06 [2] 34 1b [2] 36 1a [2] 2d 1c [2] 31 1b [2] 2d 34 }

  condition:
    any of them
}