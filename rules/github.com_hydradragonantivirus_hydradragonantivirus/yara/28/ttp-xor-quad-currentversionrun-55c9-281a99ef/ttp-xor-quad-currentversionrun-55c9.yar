rule TTP_XOR_QUAD_CurrentVersionRun_55c9 {
  strings:
    $key_55c9 = { 06 a6 [2] 22 a8 [2] 09 84 [2] 27 a6 [2] 33 bd [2] 3c a7 [2] 22 ba [2] 20 bb [2] 3b bd [2] 27 ba [2] 3b 95 }

  condition:
    any of them
}