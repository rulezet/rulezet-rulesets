rule TTP_XOR_QUAD_CurrentVersionRun_1de8 {
  strings:
    $key_1de8 = { 4e 87 [2] 6a 89 [2] 41 a5 [2] 6f 87 [2] 7b 9c [2] 74 86 [2] 6a 9b [2] 68 9a [2] 73 9c [2] 6f 9b [2] 73 b4 }

  condition:
    any of them
}