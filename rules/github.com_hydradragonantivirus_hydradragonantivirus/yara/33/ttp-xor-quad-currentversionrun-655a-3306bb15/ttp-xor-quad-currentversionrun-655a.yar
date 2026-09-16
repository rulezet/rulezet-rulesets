rule TTP_XOR_QUAD_CurrentVersionRun_655a {
  strings:
    $key_655a = { 36 35 [2] 12 3b [2] 39 17 [2] 17 35 [2] 03 2e [2] 0c 34 [2] 12 29 [2] 10 28 [2] 0b 2e [2] 17 29 [2] 0b 06 }

  condition:
    any of them
}