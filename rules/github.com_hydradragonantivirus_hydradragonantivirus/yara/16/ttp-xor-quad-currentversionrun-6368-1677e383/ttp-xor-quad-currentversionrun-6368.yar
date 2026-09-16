rule TTP_XOR_QUAD_CurrentVersionRun_6368 {
  strings:
    $key_6368 = { 30 07 [2] 14 09 [2] 3f 25 [2] 11 07 [2] 05 1c [2] 0a 06 [2] 14 1b [2] 16 1a [2] 0d 1c [2] 11 1b [2] 0d 34 }

  condition:
    any of them
}