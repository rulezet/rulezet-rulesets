rule TTP_XOR_QUAD_CurrentVersionRun_2248 {
  strings:
    $key_2248 = { 71 27 [2] 55 29 [2] 7e 05 [2] 50 27 [2] 44 3c [2] 4b 26 [2] 55 3b [2] 57 3a [2] 4c 3c [2] 50 3b [2] 4c 14 }

  condition:
    any of them
}