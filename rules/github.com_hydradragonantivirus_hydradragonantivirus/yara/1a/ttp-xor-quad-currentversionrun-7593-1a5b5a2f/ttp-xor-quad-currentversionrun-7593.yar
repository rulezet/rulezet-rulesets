rule TTP_XOR_QUAD_CurrentVersionRun_7593 {
  strings:
    $key_7593 = { 26 fc [2] 02 f2 [2] 29 de [2] 07 fc [2] 13 e7 [2] 1c fd [2] 02 e0 [2] 00 e1 [2] 1b e7 [2] 07 e0 [2] 1b cf }

  condition:
    any of them
}