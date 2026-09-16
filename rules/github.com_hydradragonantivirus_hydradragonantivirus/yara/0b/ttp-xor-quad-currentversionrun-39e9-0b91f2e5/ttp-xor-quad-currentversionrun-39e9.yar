rule TTP_XOR_QUAD_CurrentVersionRun_39e9 {
  strings:
    $key_39e9 = { 6a 86 [2] 4e 88 [2] 65 a4 [2] 4b 86 [2] 5f 9d [2] 50 87 [2] 4e 9a [2] 4c 9b [2] 57 9d [2] 4b 9a [2] 57 b5 }

  condition:
    any of them
}