rule TTP_XOR_QUAD_CurrentVersionRun_3df5 {
  strings:
    $key_3df5 = { 6e 9a [2] 4a 94 [2] 61 b8 [2] 4f 9a [2] 5b 81 [2] 54 9b [2] 4a 86 [2] 48 87 [2] 53 81 [2] 4f 86 [2] 53 a9 }

  condition:
    any of them
}