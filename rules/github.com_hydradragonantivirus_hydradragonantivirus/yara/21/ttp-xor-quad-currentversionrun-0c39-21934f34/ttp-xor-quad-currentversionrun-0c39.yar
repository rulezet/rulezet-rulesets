rule TTP_XOR_QUAD_CurrentVersionRun_0c39 {
  strings:
    $key_0c39 = { 5f 56 [2] 7b 58 [2] 50 74 [2] 7e 56 [2] 6a 4d [2] 65 57 [2] 7b 4a [2] 79 4b [2] 62 4d [2] 7e 4a [2] 62 65 }

  condition:
    any of them
}