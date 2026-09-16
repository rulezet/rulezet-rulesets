rule TTP_XOR_QUAD_CurrentVersionRun_01f8 {
  strings:
    $key_01f8 = { 52 97 [2] 76 99 [2] 5d b5 [2] 73 97 [2] 67 8c [2] 68 96 [2] 76 8b [2] 74 8a [2] 6f 8c [2] 73 8b [2] 6f a4 }

  condition:
    any of them
}