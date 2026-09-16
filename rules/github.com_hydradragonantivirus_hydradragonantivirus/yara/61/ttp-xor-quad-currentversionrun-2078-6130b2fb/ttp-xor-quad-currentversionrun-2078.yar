rule TTP_XOR_QUAD_CurrentVersionRun_2078 {
  strings:
    $key_2078 = { 73 17 [2] 57 19 [2] 7c 35 [2] 52 17 [2] 46 0c [2] 49 16 [2] 57 0b [2] 55 0a [2] 4e 0c [2] 52 0b [2] 4e 24 }

  condition:
    any of them
}