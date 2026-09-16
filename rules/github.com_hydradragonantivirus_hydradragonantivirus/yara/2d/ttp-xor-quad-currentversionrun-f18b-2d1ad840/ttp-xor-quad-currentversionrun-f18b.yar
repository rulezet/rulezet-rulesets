rule TTP_XOR_QUAD_CurrentVersionRun_f18b {
  strings:
    $key_f18b = { a2 e4 [2] 86 ea [2] ad c6 [2] 83 e4 [2] 97 ff [2] 98 e5 [2] 86 f8 [2] 84 f9 [2] 9f ff [2] 83 f8 [2] 9f d7 }

  condition:
    any of them
}