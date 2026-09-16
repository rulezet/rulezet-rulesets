rule TTP_XOR_QUAD_CurrentVersionRun_1246 {
  strings:
    $key_1246 = { 41 29 [2] 65 27 [2] 4e 0b [2] 60 29 [2] 74 32 [2] 7b 28 [2] 65 35 [2] 67 34 [2] 7c 32 [2] 60 35 [2] 7c 1a }

  condition:
    any of them
}