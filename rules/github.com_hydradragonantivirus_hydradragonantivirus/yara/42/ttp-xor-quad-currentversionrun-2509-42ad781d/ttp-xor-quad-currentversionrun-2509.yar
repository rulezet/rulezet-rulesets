rule TTP_XOR_QUAD_CurrentVersionRun_2509 {
  strings:
    $key_2509 = { 76 66 [2] 52 68 [2] 79 44 [2] 57 66 [2] 43 7d [2] 4c 67 [2] 52 7a [2] 50 7b [2] 4b 7d [2] 57 7a [2] 4b 55 }

  condition:
    any of them
}