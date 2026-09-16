rule TTP_XOR_QUAD_CurrentVersionRun_2707 {
  strings:
    $key_2707 = { 74 68 [2] 50 66 [2] 7b 4a [2] 55 68 [2] 41 73 [2] 4e 69 [2] 50 74 [2] 52 75 [2] 49 73 [2] 55 74 [2] 49 5b }

  condition:
    any of them
}