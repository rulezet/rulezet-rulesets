rule TTP_XOR_QUAD_CurrentVersionRun_2015 {
  strings:
    $key_2015 = { 73 7a [2] 57 74 [2] 7c 58 [2] 52 7a [2] 46 61 [2] 49 7b [2] 57 66 [2] 55 67 [2] 4e 61 [2] 52 66 [2] 4e 49 }

  condition:
    any of them
}