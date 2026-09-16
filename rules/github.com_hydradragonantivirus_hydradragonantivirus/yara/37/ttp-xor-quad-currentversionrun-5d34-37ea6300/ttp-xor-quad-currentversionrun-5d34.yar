rule TTP_XOR_QUAD_CurrentVersionRun_5d34 {
  strings:
    $key_5d34 = { 0e 5b [2] 2a 55 [2] 01 79 [2] 2f 5b [2] 3b 40 [2] 34 5a [2] 2a 47 [2] 28 46 [2] 33 40 [2] 2f 47 [2] 33 68 }

  condition:
    any of them
}