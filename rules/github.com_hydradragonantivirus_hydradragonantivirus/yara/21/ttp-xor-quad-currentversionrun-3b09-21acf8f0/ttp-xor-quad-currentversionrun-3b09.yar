rule TTP_XOR_QUAD_CurrentVersionRun_3b09 {
  strings:
    $key_3b09 = { 68 66 [2] 4c 68 [2] 67 44 [2] 49 66 [2] 5d 7d [2] 52 67 [2] 4c 7a [2] 4e 7b [2] 55 7d [2] 49 7a [2] 55 55 }

  condition:
    any of them
}