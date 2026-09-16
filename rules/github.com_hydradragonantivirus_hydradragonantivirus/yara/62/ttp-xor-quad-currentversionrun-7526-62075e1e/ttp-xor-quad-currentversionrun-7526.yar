rule TTP_XOR_QUAD_CurrentVersionRun_7526 {
  strings:
    $key_7526 = { 26 49 [2] 02 47 [2] 29 6b [2] 07 49 [2] 13 52 [2] 1c 48 [2] 02 55 [2] 00 54 [2] 1b 52 [2] 07 55 [2] 1b 7a }

  condition:
    any of them
}