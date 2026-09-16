rule TTP_XOR_MULT_DOSStub_9a30 {
  strings:
    $key_9a30 = { ce 58 [2] ba 40 [2] fd 42 [2] ba 53 [2] f4 5f [2] f8 55 [2] ef 5e [2] f4 10 [2] c9 }

  condition:
    any of them
}