rule TTP_XOR_QUAD_CurrentVersionRun_7e93 {
  strings:
    $key_7e93 = { 2d fc [2] 09 f2 [2] 22 de [2] 0c fc [2] 18 e7 [2] 17 fd [2] 09 e0 [2] 0b e1 [2] 10 e7 [2] 0c e0 [2] 10 cf }

  condition:
    any of them
}