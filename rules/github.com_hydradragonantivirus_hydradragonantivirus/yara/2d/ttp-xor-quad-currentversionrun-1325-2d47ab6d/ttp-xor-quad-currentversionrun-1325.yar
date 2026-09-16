rule TTP_XOR_QUAD_CurrentVersionRun_1325 {
  strings:
    $key_1325 = { 40 4a [2] 64 44 [2] 4f 68 [2] 61 4a [2] 75 51 [2] 7a 4b [2] 64 56 [2] 66 57 [2] 7d 51 [2] 61 56 [2] 7d 79 }

  condition:
    any of them
}