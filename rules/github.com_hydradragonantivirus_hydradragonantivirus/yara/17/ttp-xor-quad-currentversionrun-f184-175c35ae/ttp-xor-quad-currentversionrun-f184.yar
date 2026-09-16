rule TTP_XOR_QUAD_CurrentVersionRun_f184 {
  strings:
    $key_f184 = { a2 eb [2] 86 e5 [2] ad c9 [2] 83 eb [2] 97 f0 [2] 98 ea [2] 86 f7 [2] 84 f6 [2] 9f f0 [2] 83 f7 [2] 9f d8 }

  condition:
    any of them
}