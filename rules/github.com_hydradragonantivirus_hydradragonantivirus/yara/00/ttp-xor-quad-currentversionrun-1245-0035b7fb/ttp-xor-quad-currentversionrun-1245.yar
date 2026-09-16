rule TTP_XOR_QUAD_CurrentVersionRun_1245 {
  strings:
    $key_1245 = { 41 2a [2] 65 24 [2] 4e 08 [2] 60 2a [2] 74 31 [2] 7b 2b [2] 65 36 [2] 67 37 [2] 7c 31 [2] 60 36 [2] 7c 19 }

  condition:
    any of them
}