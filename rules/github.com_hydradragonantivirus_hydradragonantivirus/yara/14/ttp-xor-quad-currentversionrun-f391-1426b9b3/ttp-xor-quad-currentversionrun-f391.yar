rule TTP_XOR_QUAD_CurrentVersionRun_f391 {
  strings:
    $key_f391 = { a0 fe [2] 84 f0 [2] af dc [2] 81 fe [2] 95 e5 [2] 9a ff [2] 84 e2 [2] 86 e3 [2] 9d e5 [2] 81 e2 [2] 9d cd }

  condition:
    any of them
}