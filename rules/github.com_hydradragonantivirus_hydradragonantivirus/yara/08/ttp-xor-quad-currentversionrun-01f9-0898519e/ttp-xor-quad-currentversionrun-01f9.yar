rule TTP_XOR_QUAD_CurrentVersionRun_01f9 {
  strings:
    $key_01f9 = { 52 96 [2] 76 98 [2] 5d b4 [2] 73 96 [2] 67 8d [2] 68 97 [2] 76 8a [2] 74 8b [2] 6f 8d [2] 73 8a [2] 6f a5 }

  condition:
    any of them
}