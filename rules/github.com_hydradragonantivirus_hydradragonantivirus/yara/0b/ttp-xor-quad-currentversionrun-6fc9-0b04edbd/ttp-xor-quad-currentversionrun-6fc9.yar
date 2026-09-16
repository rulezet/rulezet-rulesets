rule TTP_XOR_QUAD_CurrentVersionRun_6fc9 {
  strings:
    $key_6fc9 = { 3c a6 [2] 18 a8 [2] 33 84 [2] 1d a6 [2] 09 bd [2] 06 a7 [2] 18 ba [2] 1a bb [2] 01 bd [2] 1d ba [2] 01 95 }

  condition:
    any of them
}