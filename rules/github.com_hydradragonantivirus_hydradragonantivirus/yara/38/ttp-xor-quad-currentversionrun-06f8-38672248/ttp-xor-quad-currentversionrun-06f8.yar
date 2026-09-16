rule TTP_XOR_QUAD_CurrentVersionRun_06f8 {
  strings:
    $key_06f8 = { 55 97 [2] 71 99 [2] 5a b5 [2] 74 97 [2] 60 8c [2] 6f 96 [2] 71 8b [2] 73 8a [2] 68 8c [2] 74 8b [2] 68 a4 }

  condition:
    any of them
}