rule TTP_XOR_QUAD_CurrentVersionRun_4ce5 {
  strings:
    $key_4ce5 = { 1f 8a [2] 3b 84 [2] 10 a8 [2] 3e 8a [2] 2a 91 [2] 25 8b [2] 3b 96 [2] 39 97 [2] 22 91 [2] 3e 96 [2] 22 b9 }

  condition:
    any of them
}