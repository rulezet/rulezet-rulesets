rule TTP_XOR_MULT_DOSStub_9a7c {
  strings:
    $key_9a7c = { ce 14 [2] ba 0c [2] fd 0e [2] ba 1f [2] f4 13 [2] f8 19 [2] ef 12 [2] f4 5c [2] c9 }

  condition:
    any of them
}