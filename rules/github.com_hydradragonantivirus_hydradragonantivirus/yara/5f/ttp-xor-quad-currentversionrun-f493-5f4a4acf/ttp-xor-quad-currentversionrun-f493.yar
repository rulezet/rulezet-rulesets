rule TTP_XOR_QUAD_CurrentVersionRun_f493 {
  strings:
    $key_f493 = { a7 fc [2] 83 f2 [2] a8 de [2] 86 fc [2] 92 e7 [2] 9d fd [2] 83 e0 [2] 81 e1 [2] 9a e7 [2] 86 e0 [2] 9a cf }

  condition:
    any of them
}