rule TTP_XOR_QUAD_CurrentVersionRun_0e4b {
  strings:
    $key_0e4b = { 5d 24 [2] 79 2a [2] 52 06 [2] 7c 24 [2] 68 3f [2] 67 25 [2] 79 38 [2] 7b 39 [2] 60 3f [2] 7c 38 [2] 60 17 }

  condition:
    any of them
}