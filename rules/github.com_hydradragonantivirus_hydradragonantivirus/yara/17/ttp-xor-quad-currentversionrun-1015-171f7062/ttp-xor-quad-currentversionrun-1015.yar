rule TTP_XOR_QUAD_CurrentVersionRun_1015 {
  strings:
    $key_1015 = { 43 7a [2] 67 74 [2] 4c 58 [2] 62 7a [2] 76 61 [2] 79 7b [2] 67 66 [2] 65 67 [2] 7e 61 [2] 62 66 [2] 7e 49 }

  condition:
    any of them
}