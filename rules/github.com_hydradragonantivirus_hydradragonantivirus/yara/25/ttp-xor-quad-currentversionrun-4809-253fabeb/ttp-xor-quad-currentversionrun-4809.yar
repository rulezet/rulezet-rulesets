rule TTP_XOR_QUAD_CurrentVersionRun_4809 {
  strings:
    $key_4809 = { 1b 66 [2] 3f 68 [2] 14 44 [2] 3a 66 [2] 2e 7d [2] 21 67 [2] 3f 7a [2] 3d 7b [2] 26 7d [2] 3a 7a [2] 26 55 }

  condition:
    any of them
}