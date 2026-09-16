rule TTP_XOR_QUAD_CurrentVersionRun_6693 {
  strings:
    $key_6693 = { 35 fc [2] 11 f2 [2] 3a de [2] 14 fc [2] 00 e7 [2] 0f fd [2] 11 e0 [2] 13 e1 [2] 08 e7 [2] 14 e0 [2] 08 cf }

  condition:
    any of them
}