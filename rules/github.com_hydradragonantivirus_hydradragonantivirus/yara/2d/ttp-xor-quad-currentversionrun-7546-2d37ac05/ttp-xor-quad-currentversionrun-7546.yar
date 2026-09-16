rule TTP_XOR_QUAD_CurrentVersionRun_7546 {
  strings:
    $key_7546 = { 26 29 [2] 02 27 [2] 29 0b [2] 07 29 [2] 13 32 [2] 1c 28 [2] 02 35 [2] 00 34 [2] 1b 32 [2] 07 35 [2] 1b 1a }

  condition:
    any of them
}