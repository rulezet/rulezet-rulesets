rule TTP_XOR_MULT_DOSStub_9a7f {
  strings:
    $key_9a7f = { ce 17 [2] ba 0f [2] fd 0d [2] ba 1c [2] f4 10 [2] f8 1a [2] ef 11 [2] f4 5f [2] c9 }

  condition:
    any of them
}