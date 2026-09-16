rule TTP_XOR_QUAD_CurrentVersionRun_473b {
  strings:
    $key_473b = { 14 54 [2] 30 5a [2] 1b 76 [2] 35 54 [2] 21 4f [2] 2e 55 [2] 30 48 [2] 32 49 [2] 29 4f [2] 35 48 [2] 29 67 }

  condition:
    any of them
}