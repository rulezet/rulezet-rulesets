rule TTP_XOR_MULT_DOSStub_9a36 {
  strings:
    $key_9a36 = { ce 5e [2] ba 46 [2] fd 44 [2] ba 55 [2] f4 59 [2] f8 53 [2] ef 58 [2] f4 16 [2] c9 }

  condition:
    any of them
}