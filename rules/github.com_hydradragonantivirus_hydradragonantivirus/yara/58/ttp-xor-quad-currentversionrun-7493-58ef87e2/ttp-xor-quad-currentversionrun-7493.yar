rule TTP_XOR_QUAD_CurrentVersionRun_7493 {
  strings:
    $key_7493 = { 27 fc [2] 03 f2 [2] 28 de [2] 06 fc [2] 12 e7 [2] 1d fd [2] 03 e0 [2] 01 e1 [2] 1a e7 [2] 06 e0 [2] 1a cf }

  condition:
    any of them
}