rule TTP_XOR_QUAD_CurrentVersionRun_7226 {
  strings:
    $key_7226 = { 21 49 [2] 05 47 [2] 2e 6b [2] 00 49 [2] 14 52 [2] 1b 48 [2] 05 55 [2] 07 54 [2] 1c 52 [2] 00 55 [2] 1c 7a }

  condition:
    any of them
}