rule TTP_XOR_QUAD_CurrentVersionRun_4cf9 {
  strings:
    $key_4cf9 = { 1f 96 [2] 3b 98 [2] 10 b4 [2] 3e 96 [2] 2a 8d [2] 25 97 [2] 3b 8a [2] 39 8b [2] 22 8d [2] 3e 8a [2] 22 a5 }

  condition:
    any of them
}