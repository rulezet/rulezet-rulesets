rule TTP_XOR_QUAD_CurrentVersionRun_f185 {
  strings:
    $key_f185 = { a2 ea [2] 86 e4 [2] ad c8 [2] 83 ea [2] 97 f1 [2] 98 eb [2] 86 f6 [2] 84 f7 [2] 9f f1 [2] 83 f6 [2] 9f d9 }

  condition:
    any of them
}