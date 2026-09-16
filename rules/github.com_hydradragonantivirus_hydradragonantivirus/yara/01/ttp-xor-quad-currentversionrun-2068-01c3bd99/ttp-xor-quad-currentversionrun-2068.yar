rule TTP_XOR_QUAD_CurrentVersionRun_2068 {
  strings:
    $key_2068 = { 73 07 [2] 57 09 [2] 7c 25 [2] 52 07 [2] 46 1c [2] 49 06 [2] 57 1b [2] 55 1a [2] 4e 1c [2] 52 1b [2] 4e 34 }

  condition:
    any of them
}