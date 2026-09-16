rule TTP_XOR_MULT_DOSStub_9af0 {
  strings:
    $key_9af0 = { ce 98 [2] ba 80 [2] fd 82 [2] ba 93 [2] f4 9f [2] f8 95 [2] ef 9e [2] f4 d0 [2] c9 }

  condition:
    any of them
}