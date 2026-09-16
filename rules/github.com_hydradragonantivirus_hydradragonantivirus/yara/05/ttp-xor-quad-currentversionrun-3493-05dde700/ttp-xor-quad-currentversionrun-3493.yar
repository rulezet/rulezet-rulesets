rule TTP_XOR_QUAD_CurrentVersionRun_3493 {
  strings:
    $key_3493 = { 67 fc [2] 43 f2 [2] 68 de [2] 46 fc [2] 52 e7 [2] 5d fd [2] 43 e0 [2] 41 e1 [2] 5a e7 [2] 46 e0 [2] 5a cf }

  condition:
    any of them
}