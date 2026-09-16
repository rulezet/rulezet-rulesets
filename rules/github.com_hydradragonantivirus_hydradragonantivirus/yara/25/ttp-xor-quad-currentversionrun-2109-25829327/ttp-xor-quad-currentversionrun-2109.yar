rule TTP_XOR_QUAD_CurrentVersionRun_2109 {
  strings:
    $key_2109 = { 72 66 [2] 56 68 [2] 7d 44 [2] 53 66 [2] 47 7d [2] 48 67 [2] 56 7a [2] 54 7b [2] 4f 7d [2] 53 7a [2] 4f 55 }

  condition:
    any of them
}