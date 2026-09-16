rule TTP_XOR_QUAD_CurrentVersionRun_39f8 {
  strings:
    $key_39f8 = { 6a 97 [2] 4e 99 [2] 65 b5 [2] 4b 97 [2] 5f 8c [2] 50 96 [2] 4e 8b [2] 4c 8a [2] 57 8c [2] 4b 8b [2] 57 a4 }

  condition:
    any of them
}