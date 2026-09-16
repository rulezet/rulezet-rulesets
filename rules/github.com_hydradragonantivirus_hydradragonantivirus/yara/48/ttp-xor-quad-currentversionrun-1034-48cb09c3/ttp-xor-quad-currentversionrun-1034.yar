rule TTP_XOR_QUAD_CurrentVersionRun_1034 {
  strings:
    $key_1034 = { 43 5b [2] 67 55 [2] 4c 79 [2] 62 5b [2] 76 40 [2] 79 5a [2] 67 47 [2] 65 46 [2] 7e 40 [2] 62 47 [2] 7e 68 }

  condition:
    any of them
}