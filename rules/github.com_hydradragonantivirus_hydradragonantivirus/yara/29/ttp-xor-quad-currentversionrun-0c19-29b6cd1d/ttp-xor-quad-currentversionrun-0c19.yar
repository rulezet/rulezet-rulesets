rule TTP_XOR_QUAD_CurrentVersionRun_0c19 {
  strings:
    $key_0c19 = { 5f 76 [2] 7b 78 [2] 50 54 [2] 7e 76 [2] 6a 6d [2] 65 77 [2] 7b 6a [2] 79 6b [2] 62 6d [2] 7e 6a [2] 62 45 }

  condition:
    any of them
}