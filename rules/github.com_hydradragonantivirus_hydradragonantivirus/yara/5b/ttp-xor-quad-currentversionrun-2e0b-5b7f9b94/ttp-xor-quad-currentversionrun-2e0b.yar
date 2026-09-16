rule TTP_XOR_QUAD_CurrentVersionRun_2e0b {
  strings:
    $key_2e0b = { 7d 64 [2] 59 6a [2] 72 46 [2] 5c 64 [2] 48 7f [2] 47 65 [2] 59 78 [2] 5b 79 [2] 40 7f [2] 5c 78 [2] 40 57 }

  condition:
    any of them
}