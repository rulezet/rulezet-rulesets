rule TTP_XOR_QUAD_CurrentVersionRun_1809 {
  strings:
    $key_1809 = { 4b 66 [2] 6f 68 [2] 44 44 [2] 6a 66 [2] 7e 7d [2] 71 67 [2] 6f 7a [2] 6d 7b [2] 76 7d [2] 6a 7a [2] 76 55 }

  condition:
    any of them
}