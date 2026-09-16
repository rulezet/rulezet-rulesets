rule TTP_XOR_QUAD_CurrentVersionRun_4493 {
  strings:
    $key_4493 = { 17 fc [2] 33 f2 [2] 18 de [2] 36 fc [2] 22 e7 [2] 2d fd [2] 33 e0 [2] 31 e1 [2] 2a e7 [2] 36 e0 [2] 2a cf }

  condition:
    any of them
}