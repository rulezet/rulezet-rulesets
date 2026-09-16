rule TTP_XOR_QUAD_CurrentVersionRun_251b {
  strings:
    $key_251b = { 76 74 [2] 52 7a [2] 79 56 [2] 57 74 [2] 43 6f [2] 4c 75 [2] 52 68 [2] 50 69 [2] 4b 6f [2] 57 68 [2] 4b 47 }

  condition:
    any of them
}