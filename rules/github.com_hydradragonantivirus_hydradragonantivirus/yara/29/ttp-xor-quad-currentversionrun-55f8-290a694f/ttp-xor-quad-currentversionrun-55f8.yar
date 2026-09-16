rule TTP_XOR_QUAD_CurrentVersionRun_55f8 {
  strings:
    $key_55f8 = { 06 97 [2] 22 99 [2] 09 b5 [2] 27 97 [2] 33 8c [2] 3c 96 [2] 22 8b [2] 20 8a [2] 3b 8c [2] 27 8b [2] 3b a4 }

  condition:
    any of them
}