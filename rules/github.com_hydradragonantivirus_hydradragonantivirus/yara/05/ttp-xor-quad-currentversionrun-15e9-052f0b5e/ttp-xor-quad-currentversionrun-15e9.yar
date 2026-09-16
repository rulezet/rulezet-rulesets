rule TTP_XOR_QUAD_CurrentVersionRun_15e9 {
  strings:
    $key_15e9 = { 46 86 [2] 62 88 [2] 49 a4 [2] 67 86 [2] 73 9d [2] 7c 87 [2] 62 9a [2] 60 9b [2] 7b 9d [2] 67 9a [2] 7b b5 }

  condition:
    any of them
}