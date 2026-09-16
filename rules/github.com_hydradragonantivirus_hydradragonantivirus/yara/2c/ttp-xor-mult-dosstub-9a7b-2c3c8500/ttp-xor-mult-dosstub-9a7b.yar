rule TTP_XOR_MULT_DOSStub_9a7b {
  strings:
    $key_9a7b = { ce 13 [2] ba 0b [2] fd 09 [2] ba 18 [2] f4 14 [2] f8 1e [2] ef 15 [2] f4 5b [2] c9 }

  condition:
    any of them
}