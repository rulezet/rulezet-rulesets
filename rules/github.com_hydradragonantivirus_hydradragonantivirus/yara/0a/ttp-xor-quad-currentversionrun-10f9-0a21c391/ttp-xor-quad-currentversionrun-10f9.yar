rule TTP_XOR_QUAD_CurrentVersionRun_10f9 {
  strings:
    $key_10f9 = { 43 96 [2] 67 98 [2] 4c b4 [2] 62 96 [2] 76 8d [2] 79 97 [2] 67 8a [2] 65 8b [2] 7e 8d [2] 62 8a [2] 7e a5 }

  condition:
    any of them
}