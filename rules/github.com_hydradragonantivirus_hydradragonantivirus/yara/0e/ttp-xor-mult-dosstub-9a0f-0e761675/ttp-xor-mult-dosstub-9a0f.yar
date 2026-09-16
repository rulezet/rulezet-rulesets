rule TTP_XOR_MULT_DOSStub_9a0f {
  strings:
    $key_9a0f = { ce 67 [2] ba 7f [2] fd 7d [2] ba 6c [2] f4 60 [2] f8 6a [2] ef 61 [2] f4 2f [2] c9 }

  condition:
    any of them
}