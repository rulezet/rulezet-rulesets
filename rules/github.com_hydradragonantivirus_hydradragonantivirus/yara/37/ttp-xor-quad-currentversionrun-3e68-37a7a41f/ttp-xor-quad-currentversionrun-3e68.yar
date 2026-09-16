rule TTP_XOR_QUAD_CurrentVersionRun_3e68 {
  strings:
    $key_3e68 = { 6d 07 [2] 49 09 [2] 62 25 [2] 4c 07 [2] 58 1c [2] 57 06 [2] 49 1b [2] 4b 1a [2] 50 1c [2] 4c 1b [2] 50 34 }

  condition:
    any of them
}