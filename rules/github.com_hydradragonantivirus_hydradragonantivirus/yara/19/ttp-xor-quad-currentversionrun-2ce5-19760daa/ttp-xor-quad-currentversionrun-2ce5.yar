rule TTP_XOR_QUAD_CurrentVersionRun_2ce5 {
  strings:
    $key_2ce5 = { 7f 8a [2] 5b 84 [2] 70 a8 [2] 5e 8a [2] 4a 91 [2] 45 8b [2] 5b 96 [2] 59 97 [2] 42 91 [2] 5e 96 [2] 42 b9 }

  condition:
    any of them
}