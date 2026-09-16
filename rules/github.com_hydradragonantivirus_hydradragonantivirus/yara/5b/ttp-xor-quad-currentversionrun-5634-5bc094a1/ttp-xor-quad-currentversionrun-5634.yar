rule TTP_XOR_QUAD_CurrentVersionRun_5634 {
  strings:
    $key_5634 = { 05 5b [2] 21 55 [2] 0a 79 [2] 24 5b [2] 30 40 [2] 3f 5a [2] 21 47 [2] 23 46 [2] 38 40 [2] 24 47 [2] 38 68 }

  condition:
    any of them
}