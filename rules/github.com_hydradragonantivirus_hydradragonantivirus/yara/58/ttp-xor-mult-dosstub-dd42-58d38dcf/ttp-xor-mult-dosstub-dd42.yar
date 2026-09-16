rule TTP_XOR_MULT_DOSStub_dd42 {
  strings:
    $key_dd42 = { 89 2a [2] fd 32 [2] ba 30 [2] fd 21 [2] b3 2d [2] bf 27 [2] a8 2c [2] b3 62 [2] 8e }

  condition:
    any of them
}