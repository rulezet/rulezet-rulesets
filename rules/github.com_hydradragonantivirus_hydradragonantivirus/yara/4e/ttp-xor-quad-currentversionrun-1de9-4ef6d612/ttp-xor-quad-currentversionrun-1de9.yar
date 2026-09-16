rule TTP_XOR_QUAD_CurrentVersionRun_1de9 {
  strings:
    $key_1de9 = { 4e 86 [2] 6a 88 [2] 41 a4 [2] 6f 86 [2] 7b 9d [2] 74 87 [2] 6a 9a [2] 68 9b [2] 73 9d [2] 6f 9a [2] 73 b5 }

  condition:
    any of them
}