rule TTP_XOR_QUAD_CurrentVersionRun_3b39 {
  strings:
    $key_3b39 = { 68 56 [2] 4c 58 [2] 67 74 [2] 49 56 [2] 5d 4d [2] 52 57 [2] 4c 4a [2] 4e 4b [2] 55 4d [2] 49 4a [2] 55 65 }

  condition:
    any of them
}