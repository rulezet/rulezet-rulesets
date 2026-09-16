rule TTP_XOR_QUAD_CurrentVersionRun_39e8 {
  strings:
    $key_39e8 = { 6a 87 [2] 4e 89 [2] 65 a5 [2] 4b 87 [2] 5f 9c [2] 50 86 [2] 4e 9b [2] 4c 9a [2] 57 9c [2] 4b 9b [2] 57 b4 }

  condition:
    any of them
}