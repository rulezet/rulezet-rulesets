rule TTP_XOR_QUAD_CurrentVersionRun_2e4b {
  strings:
    $key_2e4b = { 7d 24 [2] 59 2a [2] 72 06 [2] 5c 24 [2] 48 3f [2] 47 25 [2] 59 38 [2] 5b 39 [2] 40 3f [2] 5c 38 [2] 40 17 }

  condition:
    any of them
}