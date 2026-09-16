rule TTP_XOR_QUAD_CurrentVersionRun_e6c9 {
  strings:
    $key_e6c9 = { b5 a6 [2] 91 a8 [2] ba 84 [2] 94 a6 [2] 80 bd [2] 8f a7 [2] 91 ba [2] 93 bb [2] 88 bd [2] 94 ba [2] 88 95 }

  condition:
    any of them
}