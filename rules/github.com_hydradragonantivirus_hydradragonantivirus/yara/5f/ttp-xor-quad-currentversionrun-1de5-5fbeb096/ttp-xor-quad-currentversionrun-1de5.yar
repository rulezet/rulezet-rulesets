rule TTP_XOR_QUAD_CurrentVersionRun_1de5 {
  strings:
    $key_1de5 = { 4e 8a [2] 6a 84 [2] 41 a8 [2] 6f 8a [2] 7b 91 [2] 74 8b [2] 6a 96 [2] 68 97 [2] 73 91 [2] 6f 96 [2] 73 b9 }

  condition:
    any of them
}