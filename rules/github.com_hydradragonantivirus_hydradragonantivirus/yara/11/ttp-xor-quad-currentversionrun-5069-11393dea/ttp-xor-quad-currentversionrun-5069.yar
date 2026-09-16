rule TTP_XOR_QUAD_CurrentVersionRun_5069 {
  strings:
    $key_5069 = { 03 06 [2] 27 08 [2] 0c 24 [2] 22 06 [2] 36 1d [2] 39 07 [2] 27 1a [2] 25 1b [2] 3e 1d [2] 22 1a [2] 3e 35 }

  condition:
    any of them
}