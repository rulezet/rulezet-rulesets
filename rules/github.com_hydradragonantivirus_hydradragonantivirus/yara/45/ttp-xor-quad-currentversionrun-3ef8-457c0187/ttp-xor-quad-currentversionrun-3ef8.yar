rule TTP_XOR_QUAD_CurrentVersionRun_3ef8 {
  strings:
    $key_3ef8 = { 6d 97 [2] 49 99 [2] 62 b5 [2] 4c 97 [2] 58 8c [2] 57 96 [2] 49 8b [2] 4b 8a [2] 50 8c [2] 4c 8b [2] 50 a4 }

  condition:
    any of them
}