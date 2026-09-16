rule TTP_XOR_QUAD_CurrentVersionRun_791b {
  strings:
    $key_791b = { 2a 74 [2] 0e 7a [2] 25 56 [2] 0b 74 [2] 1f 6f [2] 10 75 [2] 0e 68 [2] 0c 69 [2] 17 6f [2] 0b 68 [2] 17 47 }

  condition:
    any of them
}