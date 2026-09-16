rule TTP_XOR_MULT_DOSStub_9a2f {
  strings:
    $key_9a2f = { ce 47 [2] ba 5f [2] fd 5d [2] ba 4c [2] f4 40 [2] f8 4a [2] ef 41 [2] f4 0f [2] c9 }

  condition:
    any of them
}