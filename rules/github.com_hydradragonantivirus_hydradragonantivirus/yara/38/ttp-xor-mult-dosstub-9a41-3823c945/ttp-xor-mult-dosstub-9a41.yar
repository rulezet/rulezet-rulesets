rule TTP_XOR_MULT_DOSStub_9a41 {
  strings:
    $key_9a41 = { ce 29 [2] ba 31 [2] fd 33 [2] ba 22 [2] f4 2e [2] f8 24 [2] ef 2f [2] f4 61 [2] c9 }

  condition:
    any of them
}