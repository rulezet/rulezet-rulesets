rule TTP_XOR_QUAD_CurrentVersionRun_2079 {
  strings:
    $key_2079 = { 73 16 [2] 57 18 [2] 7c 34 [2] 52 16 [2] 46 0d [2] 49 17 [2] 57 0a [2] 55 0b [2] 4e 0d [2] 52 0a [2] 4e 25 }

  condition:
    any of them
}