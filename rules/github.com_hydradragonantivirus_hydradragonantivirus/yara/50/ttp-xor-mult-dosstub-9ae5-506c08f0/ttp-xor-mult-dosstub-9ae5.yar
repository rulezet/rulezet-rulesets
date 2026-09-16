rule TTP_XOR_MULT_DOSStub_9ae5 {
  strings:
    $key_9ae5 = { ce 8d [2] ba 95 [2] fd 97 [2] ba 86 [2] f4 8a [2] f8 80 [2] ef 8b [2] f4 c5 [2] c9 }

  condition:
    any of them
}