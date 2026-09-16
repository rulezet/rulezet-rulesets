rule TTP_XOR_QUAD_CurrentVersionRun_2893 {
  strings:
    $key_2893 = { 7b fc [2] 5f f2 [2] 74 de [2] 5a fc [2] 4e e7 [2] 41 fd [2] 5f e0 [2] 5d e1 [2] 46 e7 [2] 5a e0 [2] 46 cf }

  condition:
    any of them
}