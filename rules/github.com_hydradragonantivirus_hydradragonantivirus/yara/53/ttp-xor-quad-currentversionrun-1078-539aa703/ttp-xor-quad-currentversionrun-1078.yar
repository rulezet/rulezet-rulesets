rule TTP_XOR_QUAD_CurrentVersionRun_1078 {
  strings:
    $key_1078 = { 43 17 [2] 67 19 [2] 4c 35 [2] 62 17 [2] 76 0c [2] 79 16 [2] 67 0b [2] 65 0a [2] 7e 0c [2] 62 0b [2] 7e 24 }

  condition:
    any of them
}