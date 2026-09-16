rule TTP_XOR_QUAD_CurrentVersionRun_72c9 {
  strings:
    $key_72c9 = { 21 a6 [2] 05 a8 [2] 2e 84 [2] 00 a6 [2] 14 bd [2] 1b a7 [2] 05 ba [2] 07 bb [2] 1c bd [2] 00 ba [2] 1c 95 }

  condition:
    any of them
}