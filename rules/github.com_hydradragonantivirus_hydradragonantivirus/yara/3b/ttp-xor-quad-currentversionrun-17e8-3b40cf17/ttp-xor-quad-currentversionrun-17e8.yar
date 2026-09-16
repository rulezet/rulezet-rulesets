rule TTP_XOR_QUAD_CurrentVersionRun_17e8 {
  strings:
    $key_17e8 = { 44 87 [2] 60 89 [2] 4b a5 [2] 65 87 [2] 71 9c [2] 7e 86 [2] 60 9b [2] 62 9a [2] 79 9c [2] 65 9b [2] 79 b4 }

  condition:
    any of them
}