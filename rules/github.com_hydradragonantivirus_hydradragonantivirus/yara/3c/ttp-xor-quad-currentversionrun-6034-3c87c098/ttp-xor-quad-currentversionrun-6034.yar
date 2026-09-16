rule TTP_XOR_QUAD_CurrentVersionRun_6034 {
  strings:
    $key_6034 = { 33 5b [2] 17 55 [2] 3c 79 [2] 12 5b [2] 06 40 [2] 09 5a [2] 17 47 [2] 15 46 [2] 0e 40 [2] 12 47 [2] 0e 68 }

  condition:
    any of them
}