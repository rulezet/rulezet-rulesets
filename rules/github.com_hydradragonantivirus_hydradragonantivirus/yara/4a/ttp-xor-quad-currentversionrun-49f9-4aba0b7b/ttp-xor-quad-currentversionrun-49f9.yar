rule TTP_XOR_QUAD_CurrentVersionRun_49f9 {
  strings:
    $key_49f9 = { 1a 96 [2] 3e 98 [2] 15 b4 [2] 3b 96 [2] 2f 8d [2] 20 97 [2] 3e 8a [2] 3c 8b [2] 27 8d [2] 3b 8a [2] 27 a5 }

  condition:
    any of them
}