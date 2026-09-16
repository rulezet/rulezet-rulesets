rule TTP_XOR_QUAD_CurrentVersionRun_6ce5 {
  strings:
    $key_6ce5 = { 3f 8a [2] 1b 84 [2] 30 a8 [2] 1e 8a [2] 0a 91 [2] 05 8b [2] 1b 96 [2] 19 97 [2] 02 91 [2] 1e 96 [2] 02 b9 }

  condition:
    any of them
}