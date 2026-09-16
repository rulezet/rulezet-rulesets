rule TTP_XOR_QUAD_CurrentVersionRun_3978 {
  strings:
    $key_3978 = { 6a 17 [2] 4e 19 [2] 65 35 [2] 4b 17 [2] 5f 0c [2] 50 16 [2] 4e 0b [2] 4c 0a [2] 57 0c [2] 4b 0b [2] 57 24 }

  condition:
    any of them
}