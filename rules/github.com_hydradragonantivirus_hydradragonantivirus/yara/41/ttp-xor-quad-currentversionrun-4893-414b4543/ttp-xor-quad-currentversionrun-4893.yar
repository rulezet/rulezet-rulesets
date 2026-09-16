rule TTP_XOR_QUAD_CurrentVersionRun_4893 {
  strings:
    $key_4893 = { 1b fc [2] 3f f2 [2] 14 de [2] 3a fc [2] 2e e7 [2] 21 fd [2] 3f e0 [2] 3d e1 [2] 26 e7 [2] 3a e0 [2] 26 cf }

  condition:
    any of them
}