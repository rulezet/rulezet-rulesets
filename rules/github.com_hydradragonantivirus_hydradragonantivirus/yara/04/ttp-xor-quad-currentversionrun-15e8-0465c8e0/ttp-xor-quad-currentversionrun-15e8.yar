rule TTP_XOR_QUAD_CurrentVersionRun_15e8 {
  strings:
    $key_15e8 = { 46 87 [2] 62 89 [2] 49 a5 [2] 67 87 [2] 73 9c [2] 7c 86 [2] 62 9b [2] 60 9a [2] 7b 9c [2] 67 9b [2] 7b b4 }

  condition:
    any of them
}