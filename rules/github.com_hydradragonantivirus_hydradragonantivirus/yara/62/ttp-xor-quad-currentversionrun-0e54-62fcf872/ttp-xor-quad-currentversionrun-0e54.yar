rule TTP_XOR_QUAD_CurrentVersionRun_0e54 {
  strings:
    $key_0e54 = { 5d 3b [2] 79 35 [2] 52 19 [2] 7c 3b [2] 68 20 [2] 67 3a [2] 79 27 [2] 7b 26 [2] 60 20 [2] 7c 27 [2] 60 08 }

  condition:
    any of them
}