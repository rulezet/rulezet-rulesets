rule TTP_XOR_QUAD_CurrentVersionRun_89d4 {
  strings:
    $key_89d4 = { da bb [2] fe b5 [2] d5 99 [2] fb bb [2] ef a0 [2] e0 ba [2] fe a7 [2] fc a6 [2] e7 a0 [2] fb a7 [2] e7 88 }

  condition:
    any of them
}