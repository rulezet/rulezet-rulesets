rule TTP_XOR_MULT_DOSStub_9a00 {
  strings:
    $key_9a00 = { ce 68 [2] ba 70 [2] fd 72 [2] ba 63 [2] f4 6f [2] f8 65 [2] ef 6e [2] f4 20 [2] c9 }

  condition:
    any of them
}