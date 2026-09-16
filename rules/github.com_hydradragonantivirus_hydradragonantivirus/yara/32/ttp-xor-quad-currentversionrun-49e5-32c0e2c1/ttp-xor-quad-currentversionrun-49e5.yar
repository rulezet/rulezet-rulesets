rule TTP_XOR_QUAD_CurrentVersionRun_49e5 {
  strings:
    $key_49e5 = { 1a 8a [2] 3e 84 [2] 15 a8 [2] 3b 8a [2] 2f 91 [2] 20 8b [2] 3e 96 [2] 3c 97 [2] 27 91 [2] 3b 96 [2] 27 b9 }

  condition:
    any of them
}