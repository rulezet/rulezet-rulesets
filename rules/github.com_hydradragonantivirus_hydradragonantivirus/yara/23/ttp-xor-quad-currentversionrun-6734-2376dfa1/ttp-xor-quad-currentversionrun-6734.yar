rule TTP_XOR_QUAD_CurrentVersionRun_6734 {
  strings:
    $key_6734 = { 34 5b [2] 10 55 [2] 3b 79 [2] 15 5b [2] 01 40 [2] 0e 5a [2] 10 47 [2] 12 46 [2] 09 40 [2] 15 47 [2] 09 68 }

  condition:
    any of them
}