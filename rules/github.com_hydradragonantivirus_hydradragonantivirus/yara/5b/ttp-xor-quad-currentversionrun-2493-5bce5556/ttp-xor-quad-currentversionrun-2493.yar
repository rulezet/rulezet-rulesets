rule TTP_XOR_QUAD_CurrentVersionRun_2493 {
  strings:
    $key_2493 = { 77 fc [2] 53 f2 [2] 78 de [2] 56 fc [2] 42 e7 [2] 4d fd [2] 53 e0 [2] 51 e1 [2] 4a e7 [2] 56 e0 [2] 4a cf }

  condition:
    any of them
}