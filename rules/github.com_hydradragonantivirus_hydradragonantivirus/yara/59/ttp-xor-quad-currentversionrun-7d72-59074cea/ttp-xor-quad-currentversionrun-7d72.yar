rule TTP_XOR_QUAD_CurrentVersionRun_7d72 {
  strings:
    $key_7d72 = { 2e 1d [2] 0a 13 [2] 21 3f [2] 0f 1d [2] 1b 06 [2] 14 1c [2] 0a 01 [2] 08 00 [2] 13 06 [2] 0f 01 [2] 13 2e }

  condition:
    any of them
}