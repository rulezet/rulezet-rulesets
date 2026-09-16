rule TTP_XOR_MULT_DOSStub_9aeb {
  strings:
    $key_9aeb = { ce 83 [2] ba 9b [2] fd 99 [2] ba 88 [2] f4 84 [2] f8 8e [2] ef 85 [2] f4 cb [2] c9 }

  condition:
    any of them
}