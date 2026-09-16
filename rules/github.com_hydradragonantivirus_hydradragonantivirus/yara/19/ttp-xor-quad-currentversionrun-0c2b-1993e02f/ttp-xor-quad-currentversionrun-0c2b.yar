rule TTP_XOR_QUAD_CurrentVersionRun_0c2b {
  strings:
    $key_0c2b = { 5f 44 [2] 7b 4a [2] 50 66 [2] 7e 44 [2] 6a 5f [2] 65 45 [2] 7b 58 [2] 79 59 [2] 62 5f [2] 7e 58 [2] 62 77 }

  condition:
    any of them
}