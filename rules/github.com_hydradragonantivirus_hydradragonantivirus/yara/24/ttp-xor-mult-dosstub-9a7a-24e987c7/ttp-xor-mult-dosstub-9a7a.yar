rule TTP_XOR_MULT_DOSStub_9a7a {
  strings:
    $key_9a7a = { ce 12 [2] ba 0a [2] fd 08 [2] ba 19 [2] f4 15 [2] f8 1f [2] ef 14 [2] f4 5a [2] c9 }

  condition:
    any of them
}