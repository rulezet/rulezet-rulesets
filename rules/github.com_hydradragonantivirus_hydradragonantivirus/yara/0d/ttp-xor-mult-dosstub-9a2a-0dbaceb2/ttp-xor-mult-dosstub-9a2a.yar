rule TTP_XOR_MULT_DOSStub_9a2a {
  strings:
    $key_9a2a = { ce 42 [2] ba 5a [2] fd 58 [2] ba 49 [2] f4 45 [2] f8 4f [2] ef 44 [2] f4 0a [2] c9 }

  condition:
    any of them
}