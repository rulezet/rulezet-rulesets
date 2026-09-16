rule TTP_XOR_QUAD_CurrentVersionRun_2734 {
  strings:
    $key_2734 = { 74 5b [2] 50 55 [2] 7b 79 [2] 55 5b [2] 41 40 [2] 4e 5a [2] 50 47 [2] 52 46 [2] 49 40 [2] 55 47 [2] 49 68 }

  condition:
    any of them
}