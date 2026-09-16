rule TTP_XOR_QUAD_CurrentVersionRun_2754 {
  strings:
    $key_2754 = { 74 3b [2] 50 35 [2] 7b 19 [2] 55 3b [2] 41 20 [2] 4e 3a [2] 50 27 [2] 52 26 [2] 49 20 [2] 55 27 [2] 49 08 }

  condition:
    any of them
}