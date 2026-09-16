rule TTP_XOR_MULT_DOSStub_f142 {
  strings:
    $key_f142 = { a5 2a [2] d1 32 [2] 96 30 [2] d1 21 [2] 9f 2d [2] 93 27 [2] 84 2c [2] 9f 62 [2] a2 }

  condition:
    any of them
}