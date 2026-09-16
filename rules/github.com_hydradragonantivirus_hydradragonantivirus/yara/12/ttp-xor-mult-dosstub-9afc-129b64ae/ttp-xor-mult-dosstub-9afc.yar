rule TTP_XOR_MULT_DOSStub_9afc {
  strings:
    $key_9afc = { ce 94 [2] ba 8c [2] fd 8e [2] ba 9f [2] f4 93 [2] f8 99 [2] ef 92 [2] f4 dc [2] c9 }

  condition:
    any of them
}