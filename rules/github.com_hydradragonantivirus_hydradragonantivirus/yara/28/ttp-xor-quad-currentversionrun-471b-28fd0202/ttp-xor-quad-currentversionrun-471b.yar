rule TTP_XOR_QUAD_CurrentVersionRun_471b {
  strings:
    $key_471b = { 14 74 [2] 30 7a [2] 1b 56 [2] 35 74 [2] 21 6f [2] 2e 75 [2] 30 68 [2] 32 69 [2] 29 6f [2] 35 68 [2] 29 47 }

  condition:
    any of them
}