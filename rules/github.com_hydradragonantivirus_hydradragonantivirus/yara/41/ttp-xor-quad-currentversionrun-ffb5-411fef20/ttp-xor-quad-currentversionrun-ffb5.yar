rule TTP_XOR_QUAD_CurrentVersionRun_ffb5 {
  strings:
    $key_ffb5 = { ac da [2] 88 d4 [2] a3 f8 [2] 8d da [2] 99 c1 [2] 96 db [2] 88 c6 [2] 8a c7 [2] 91 c1 [2] 8d c6 [2] 91 e9 }

  condition:
    any of them
}