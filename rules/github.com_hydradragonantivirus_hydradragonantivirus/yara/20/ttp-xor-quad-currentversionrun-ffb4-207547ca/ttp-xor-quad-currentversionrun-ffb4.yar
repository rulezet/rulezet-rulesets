rule TTP_XOR_QUAD_CurrentVersionRun_ffb4 {
  strings:
    $key_ffb4 = { ac db [2] 88 d5 [2] a3 f9 [2] 8d db [2] 99 c0 [2] 96 da [2] 88 c7 [2] 8a c6 [2] 91 c0 [2] 8d c7 [2] 91 e8 }

  condition:
    any of them
}