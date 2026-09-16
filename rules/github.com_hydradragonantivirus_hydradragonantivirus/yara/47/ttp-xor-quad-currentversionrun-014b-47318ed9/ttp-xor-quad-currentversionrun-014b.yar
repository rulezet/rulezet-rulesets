rule TTP_XOR_QUAD_CurrentVersionRun_014b {
  strings:
    $key_014b = { 52 24 [2] 76 2a [2] 5d 06 [2] 73 24 [2] 67 3f [2] 68 25 [2] 76 38 [2] 74 39 [2] 6f 3f [2] 73 38 [2] 6f 17 }

  condition:
    any of them
}