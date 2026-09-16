rule TTP_XOR_QUAD_CurrentVersionRun_5546 {
  strings:
    $key_5546 = { 06 29 [2] 22 27 [2] 09 0b [2] 27 29 [2] 33 32 [2] 3c 28 [2] 22 35 [2] 20 34 [2] 3b 32 [2] 27 35 [2] 3b 1a }

  condition:
    any of them
}