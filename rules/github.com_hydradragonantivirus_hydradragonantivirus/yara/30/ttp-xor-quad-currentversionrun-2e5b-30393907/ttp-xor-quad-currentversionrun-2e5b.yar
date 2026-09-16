rule TTP_XOR_QUAD_CurrentVersionRun_2e5b {
  strings:
    $key_2e5b = { 7d 34 [2] 59 3a [2] 72 16 [2] 5c 34 [2] 48 2f [2] 47 35 [2] 59 28 [2] 5b 29 [2] 40 2f [2] 5c 28 [2] 40 07 }

  condition:
    any of them
}