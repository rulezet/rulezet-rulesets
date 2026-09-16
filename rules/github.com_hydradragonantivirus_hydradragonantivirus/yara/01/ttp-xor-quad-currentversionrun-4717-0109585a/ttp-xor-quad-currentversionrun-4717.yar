rule TTP_XOR_QUAD_CurrentVersionRun_4717 {
  strings:
    $key_4717 = { 14 78 [2] 30 76 [2] 1b 5a [2] 35 78 [2] 21 63 [2] 2e 79 [2] 30 64 [2] 32 65 [2] 29 63 [2] 35 64 [2] 29 4b }

  condition:
    any of them
}