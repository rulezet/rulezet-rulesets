rule TTP_XOR_QUAD_CurrentVersionRun_0e68 {
  strings:
    $key_0e68 = { 5d 07 [2] 79 09 [2] 52 25 [2] 7c 07 [2] 68 1c [2] 67 06 [2] 79 1b [2] 7b 1a [2] 60 1c [2] 7c 1b [2] 60 34 }

  condition:
    any of them
}