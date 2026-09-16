rule TTP_XOR_QUAD_CurrentVersionRun_2009 {
  strings:
    $key_2009 = { 73 66 [2] 57 68 [2] 7c 44 [2] 52 66 [2] 46 7d [2] 49 67 [2] 57 7a [2] 55 7b [2] 4e 7d [2] 52 7a [2] 4e 55 }

  condition:
    any of them
}