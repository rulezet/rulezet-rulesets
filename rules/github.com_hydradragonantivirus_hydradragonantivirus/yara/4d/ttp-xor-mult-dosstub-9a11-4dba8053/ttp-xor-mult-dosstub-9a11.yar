rule TTP_XOR_MULT_DOSStub_9a11 {
  strings:
    $key_9a11 = { ce 79 [2] ba 61 [2] fd 63 [2] ba 72 [2] f4 7e [2] f8 74 [2] ef 7f [2] f4 31 [2] c9 }

  condition:
    any of them
}