rule TTP_XOR_MULT_DOSStub_9a6a {
  strings:
    $key_9a6a = { ce 02 [2] ba 1a [2] fd 18 [2] ba 09 [2] f4 05 [2] f8 0f [2] ef 04 [2] f4 4a [2] c9 }

  condition:
    any of them
}