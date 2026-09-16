rule TTP_XOR_QUAD_CurrentVersionRun_7b34 {
  strings:
    $key_7b34 = { 28 5b [2] 0c 55 [2] 27 79 [2] 09 5b [2] 1d 40 [2] 12 5a [2] 0c 47 [2] 0e 46 [2] 15 40 [2] 09 47 [2] 15 68 }

  condition:
    any of them
}