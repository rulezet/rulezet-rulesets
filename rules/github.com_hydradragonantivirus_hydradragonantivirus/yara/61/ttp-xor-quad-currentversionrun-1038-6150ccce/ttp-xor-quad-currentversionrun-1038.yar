rule TTP_XOR_QUAD_CurrentVersionRun_1038 {
  strings:
    $key_1038 = { 43 57 [2] 67 59 [2] 4c 75 [2] 62 57 [2] 76 4c [2] 79 56 [2] 67 4b [2] 65 4a [2] 7e 4c [2] 62 4b [2] 7e 64 }

  condition:
    any of them
}