rule TTP_XOR_QUAD_CurrentVersionRun_695b {
  strings:
    $key_695b = { 3a 34 [2] 1e 3a [2] 35 16 [2] 1b 34 [2] 0f 2f [2] 00 35 [2] 1e 28 [2] 1c 29 [2] 07 2f [2] 1b 28 [2] 07 07 }

  condition:
    any of them
}