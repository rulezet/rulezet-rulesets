rule TTP_XOR_QUAD_CurrentVersionRun_1509 {
  strings:
    $key_1509 = { 46 66 [2] 62 68 [2] 49 44 [2] 67 66 [2] 73 7d [2] 7c 67 [2] 62 7a [2] 60 7b [2] 7b 7d [2] 67 7a [2] 7b 55 }

  condition:
    any of them
}