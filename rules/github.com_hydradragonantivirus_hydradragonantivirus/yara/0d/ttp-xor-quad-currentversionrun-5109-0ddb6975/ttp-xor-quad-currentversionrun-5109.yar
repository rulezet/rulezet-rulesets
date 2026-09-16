rule TTP_XOR_QUAD_CurrentVersionRun_5109 {
  strings:
    $key_5109 = { 02 66 [2] 26 68 [2] 0d 44 [2] 23 66 [2] 37 7d [2] 38 67 [2] 26 7a [2] 24 7b [2] 3f 7d [2] 23 7a [2] 3f 55 }

  condition:
    any of them
}