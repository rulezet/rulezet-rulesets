rule TTP_XOR_QUAD_CurrentVersionRun_4468 {
  strings:
    $key_4468 = { 17 07 [2] 33 09 [2] 18 25 [2] 36 07 [2] 22 1c [2] 2d 06 [2] 33 1b [2] 31 1a [2] 2a 1c [2] 36 1b [2] 2a 34 }

  condition:
    any of them
}