rule TTP_XOR_MULT_DOSStub_9a37 {
  strings:
    $key_9a37 = { ce 5f [2] ba 47 [2] fd 45 [2] ba 54 [2] f4 58 [2] f8 52 [2] ef 59 [2] f4 17 [2] c9 }

  condition:
    any of them
}