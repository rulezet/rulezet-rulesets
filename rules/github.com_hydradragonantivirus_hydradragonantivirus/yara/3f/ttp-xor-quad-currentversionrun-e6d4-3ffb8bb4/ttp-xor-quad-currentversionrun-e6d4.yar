rule TTP_XOR_QUAD_CurrentVersionRun_e6d4 {
  strings:
    $key_e6d4 = { b5 bb [2] 91 b5 [2] ba 99 [2] 94 bb [2] 80 a0 [2] 8f ba [2] 91 a7 [2] 93 a6 [2] 88 a0 [2] 94 a7 [2] 88 88 }

  condition:
    any of them
}