rule TTP_XOR_MULT_DOSStub_9a16 {
  strings:
    $key_9a16 = { ce 7e [2] ba 66 [2] fd 64 [2] ba 75 [2] f4 79 [2] f8 73 [2] ef 78 [2] f4 36 [2] c9 }

  condition:
    any of them
}