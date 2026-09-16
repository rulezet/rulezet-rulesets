rule TTP_XOR_MULT_DOSStub_9a17 {
  strings:
    $key_9a17 = { ce 7f [2] ba 67 [2] fd 65 [2] ba 74 [2] f4 78 [2] f8 72 [2] ef 79 [2] f4 37 [2] c9 }

  condition:
    any of them
}