rule TTP_XOR_QUAD_CurrentVersionRun_77d5 {
  strings:
    $key_77d5 = { 24 ba [2] 00 b4 [2] 2b 98 [2] 05 ba [2] 11 a1 [2] 1e bb [2] 00 a6 [2] 02 a7 [2] 19 a1 [2] 05 a6 [2] 19 89 }

  condition:
    any of them
}