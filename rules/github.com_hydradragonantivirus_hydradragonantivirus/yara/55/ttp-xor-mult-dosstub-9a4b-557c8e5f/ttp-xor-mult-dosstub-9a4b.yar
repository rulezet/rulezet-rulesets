rule TTP_XOR_MULT_DOSStub_9a4b {
  strings:
    $key_9a4b = { ce 23 [2] ba 3b [2] fd 39 [2] ba 28 [2] f4 24 [2] f8 2e [2] ef 25 [2] f4 6b [2] c9 }

  condition:
    any of them
}