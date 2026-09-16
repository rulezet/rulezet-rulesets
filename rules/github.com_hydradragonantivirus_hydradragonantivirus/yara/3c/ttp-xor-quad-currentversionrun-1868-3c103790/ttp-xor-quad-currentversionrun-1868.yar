rule TTP_XOR_QUAD_CurrentVersionRun_1868 {
  strings:
    $key_1868 = { 4b 07 [2] 6f 09 [2] 44 25 [2] 6a 07 [2] 7e 1c [2] 71 06 [2] 6f 1b [2] 6d 1a [2] 76 1c [2] 6a 1b [2] 76 34 }

  condition:
    any of them
}