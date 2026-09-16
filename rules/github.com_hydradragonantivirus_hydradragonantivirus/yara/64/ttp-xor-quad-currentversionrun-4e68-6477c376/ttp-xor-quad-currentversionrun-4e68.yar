rule TTP_XOR_QUAD_CurrentVersionRun_4e68 {
  strings:
    $key_4e68 = { 1d 07 [2] 39 09 [2] 12 25 [2] 3c 07 [2] 28 1c [2] 27 06 [2] 39 1b [2] 3b 1a [2] 20 1c [2] 3c 1b [2] 20 34 }

  condition:
    any of them
}