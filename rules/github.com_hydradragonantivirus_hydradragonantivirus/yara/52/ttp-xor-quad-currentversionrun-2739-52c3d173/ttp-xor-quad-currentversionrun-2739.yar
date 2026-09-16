rule TTP_XOR_QUAD_CurrentVersionRun_2739 {
  strings:
    $key_2739 = { 74 56 [2] 50 58 [2] 7b 74 [2] 55 56 [2] 41 4d [2] 4e 57 [2] 50 4a [2] 52 4b [2] 49 4d [2] 55 4a [2] 49 65 }

  condition:
    any of them
}