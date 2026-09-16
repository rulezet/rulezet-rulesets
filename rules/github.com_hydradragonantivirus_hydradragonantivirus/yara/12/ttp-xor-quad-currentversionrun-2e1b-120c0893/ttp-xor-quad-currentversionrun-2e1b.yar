rule TTP_XOR_QUAD_CurrentVersionRun_2e1b {
  strings:
    $key_2e1b = { 7d 74 [2] 59 7a [2] 72 56 [2] 5c 74 [2] 48 6f [2] 47 75 [2] 59 68 [2] 5b 69 [2] 40 6f [2] 5c 68 [2] 40 47 }

  condition:
    any of them
}