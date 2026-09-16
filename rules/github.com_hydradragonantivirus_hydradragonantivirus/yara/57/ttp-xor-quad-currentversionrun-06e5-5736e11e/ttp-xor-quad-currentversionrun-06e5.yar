rule TTP_XOR_QUAD_CurrentVersionRun_06e5 {
  strings:
    $key_06e5 = { 55 8a [2] 71 84 [2] 5a a8 [2] 74 8a [2] 60 91 [2] 6f 8b [2] 71 96 [2] 73 97 [2] 68 91 [2] 74 96 [2] 68 b9 }

  condition:
    any of them
}