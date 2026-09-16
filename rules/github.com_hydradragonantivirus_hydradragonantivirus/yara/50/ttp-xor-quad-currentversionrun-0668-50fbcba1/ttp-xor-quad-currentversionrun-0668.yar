rule TTP_XOR_QUAD_CurrentVersionRun_0668 {
  strings:
    $key_0668 = { 55 07 [2] 71 09 [2] 5a 25 [2] 74 07 [2] 60 1c [2] 6f 06 [2] 71 1b [2] 73 1a [2] 68 1c [2] 74 1b [2] 68 34 }

  condition:
    any of them
}