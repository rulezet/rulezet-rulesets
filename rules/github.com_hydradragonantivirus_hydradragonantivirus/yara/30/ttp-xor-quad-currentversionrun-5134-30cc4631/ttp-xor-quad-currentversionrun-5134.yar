rule TTP_XOR_QUAD_CurrentVersionRun_5134 {
  strings:
    $key_5134 = { 02 5b [2] 26 55 [2] 0d 79 [2] 23 5b [2] 37 40 [2] 38 5a [2] 26 47 [2] 24 46 [2] 3f 40 [2] 23 47 [2] 3f 68 }

  condition:
    any of them
}