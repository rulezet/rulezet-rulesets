rule TTP_XOR_QUAD_CurrentVersionRun_3468 {
  strings:
    $key_3468 = { 67 07 [2] 43 09 [2] 68 25 [2] 46 07 [2] 52 1c [2] 5d 06 [2] 43 1b [2] 41 1a [2] 5a 1c [2] 46 1b [2] 5a 34 }

  condition:
    any of them
}