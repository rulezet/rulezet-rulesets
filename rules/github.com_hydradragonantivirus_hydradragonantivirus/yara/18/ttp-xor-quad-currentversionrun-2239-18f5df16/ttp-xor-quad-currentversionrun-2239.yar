rule TTP_XOR_QUAD_CurrentVersionRun_2239 {
  strings:
    $key_2239 = { 71 56 [2] 55 58 [2] 7e 74 [2] 50 56 [2] 44 4d [2] 4b 57 [2] 55 4a [2] 57 4b [2] 4c 4d [2] 50 4a [2] 4c 65 }

  condition:
    any of them
}