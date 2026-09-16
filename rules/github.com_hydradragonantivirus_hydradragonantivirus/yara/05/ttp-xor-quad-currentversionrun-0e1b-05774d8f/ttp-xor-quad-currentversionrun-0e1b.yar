rule TTP_XOR_QUAD_CurrentVersionRun_0e1b {
  strings:
    $key_0e1b = { 5d 74 [2] 79 7a [2] 52 56 [2] 7c 74 [2] 68 6f [2] 67 75 [2] 79 68 [2] 7b 69 [2] 60 6f [2] 7c 68 [2] 60 47 }

  condition:
    any of them
}