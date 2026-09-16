rule TTP_XOR_QUAD_CurrentVersionRun_5cf2 {
  strings:
    $key_5cf2 = { 0f 9d [2] 2b 93 [2] 00 bf [2] 2e 9d [2] 3a 86 [2] 35 9c [2] 2b 81 [2] 29 80 [2] 32 86 [2] 2e 81 [2] 32 ae }

  condition:
    any of them
}