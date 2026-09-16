rule TTP_XOR_QUAD_CurrentVersionRun_3325 {
  strings:
    $key_3325 = { 60 4a [2] 44 44 [2] 6f 68 [2] 41 4a [2] 55 51 [2] 5a 4b [2] 44 56 [2] 46 57 [2] 5d 51 [2] 41 56 [2] 5d 79 }

  condition:
    any of them
}