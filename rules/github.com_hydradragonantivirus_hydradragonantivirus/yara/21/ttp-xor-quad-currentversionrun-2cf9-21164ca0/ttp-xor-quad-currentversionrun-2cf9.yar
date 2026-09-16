rule TTP_XOR_QUAD_CurrentVersionRun_2cf9 {
  strings:
    $key_2cf9 = { 7f 96 [2] 5b 98 [2] 70 b4 [2] 5e 96 [2] 4a 8d [2] 45 97 [2] 5b 8a [2] 59 8b [2] 42 8d [2] 5e 8a [2] 42 a5 }

  condition:
    any of them
}