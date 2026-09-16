rule TTP_XOR_QUAD_CurrentVersionRun_0639 {
  strings:
    $key_0639 = { 55 56 [2] 71 58 [2] 5a 74 [2] 74 56 [2] 60 4d [2] 6f 57 [2] 71 4a [2] 73 4b [2] 68 4d [2] 74 4a [2] 68 65 }

  condition:
    any of them
}