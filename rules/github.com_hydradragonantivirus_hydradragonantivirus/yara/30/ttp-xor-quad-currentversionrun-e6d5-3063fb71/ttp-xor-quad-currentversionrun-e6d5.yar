rule TTP_XOR_QUAD_CurrentVersionRun_e6d5 {
  strings:
    $key_e6d5 = { b5 ba [2] 91 b4 [2] ba 98 [2] 94 ba [2] 80 a1 [2] 8f bb [2] 91 a6 [2] 93 a7 [2] 88 a1 [2] 94 a6 [2] 88 89 }

  condition:
    any of them
}