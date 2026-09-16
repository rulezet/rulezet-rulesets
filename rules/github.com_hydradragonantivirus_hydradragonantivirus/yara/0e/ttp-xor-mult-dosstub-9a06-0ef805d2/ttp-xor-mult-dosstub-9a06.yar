rule TTP_XOR_MULT_DOSStub_9a06 {
  strings:
    $key_9a06 = { ce 6e [2] ba 76 [2] fd 74 [2] ba 65 [2] f4 69 [2] f8 63 [2] ef 68 [2] f4 26 [2] c9 }

  condition:
    any of them
}