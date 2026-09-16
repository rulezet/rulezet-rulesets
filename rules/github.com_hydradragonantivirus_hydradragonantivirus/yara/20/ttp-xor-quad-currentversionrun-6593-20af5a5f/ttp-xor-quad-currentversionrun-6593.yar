rule TTP_XOR_QUAD_CurrentVersionRun_6593 {
  strings:
    $key_6593 = { 36 fc [2] 12 f2 [2] 39 de [2] 17 fc [2] 03 e7 [2] 0c fd [2] 12 e0 [2] 10 e1 [2] 0b e7 [2] 17 e0 [2] 0b cf }

  condition:
    any of them
}