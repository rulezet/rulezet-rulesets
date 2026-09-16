rule TTP_XOR_QUAD_CurrentVersionRun_c8a8 {
  strings:
    $key_c8a8 = { 9b c7 [2] bf c9 [2] 94 e5 [2] ba c7 [2] ae dc [2] a1 c6 [2] bf db [2] bd da [2] a6 dc [2] ba db [2] a6 f4 }

  condition:
    any of them
}