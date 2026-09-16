rule TTP_XOR_QUAD_CurrentVersionRun_3b69 {
  strings:
    $key_3b69 = { 68 06 [2] 4c 08 [2] 67 24 [2] 49 06 [2] 5d 1d [2] 52 07 [2] 4c 1a [2] 4e 1b [2] 55 1d [2] 49 1a [2] 55 35 }

  condition:
    any of them
}