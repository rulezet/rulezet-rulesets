rule TTP_XOR_QUAD_CurrentVersionRun_5893 {
  strings:
    $key_5893 = { 0b fc [2] 2f f2 [2] 04 de [2] 2a fc [2] 3e e7 [2] 31 fd [2] 2f e0 [2] 2d e1 [2] 36 e7 [2] 2a e0 [2] 36 cf }

  condition:
    any of them
}