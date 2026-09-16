rule TTP_XOR_QUAD_CurrentVersionRun_0439 {
  strings:
    $key_0439 = { 57 56 [2] 73 58 [2] 58 74 [2] 76 56 [2] 62 4d [2] 6d 57 [2] 73 4a [2] 71 4b [2] 6a 4d [2] 76 4a [2] 6a 65 }

  condition:
    any of them
}