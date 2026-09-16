rule TTP_XOR_QUAD_CurrentVersionRun_0c25 {
  strings:
    $key_0c25 = { 5f 4a [2] 7b 44 [2] 50 68 [2] 7e 4a [2] 6a 51 [2] 65 4b [2] 7b 56 [2] 79 57 [2] 62 51 [2] 7e 56 [2] 62 79 }

  condition:
    any of them
}