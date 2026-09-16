rule TTP_XOR_QUAD_CurrentVersionRun_2693 {
  strings:
    $key_2693 = { 75 fc [2] 51 f2 [2] 7a de [2] 54 fc [2] 40 e7 [2] 4f fd [2] 51 e0 [2] 53 e1 [2] 48 e7 [2] 54 e0 [2] 48 cf }

  condition:
    any of them
}