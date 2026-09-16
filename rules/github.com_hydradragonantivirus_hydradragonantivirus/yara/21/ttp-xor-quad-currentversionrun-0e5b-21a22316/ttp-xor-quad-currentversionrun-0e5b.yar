rule TTP_XOR_QUAD_CurrentVersionRun_0e5b {
  strings:
    $key_0e5b = { 5d 34 [2] 79 3a [2] 52 16 [2] 7c 34 [2] 68 2f [2] 67 35 [2] 79 28 [2] 7b 29 [2] 60 2f [2] 7c 28 [2] 60 07 }

  condition:
    any of them
}