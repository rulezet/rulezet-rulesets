rule TTP_XOR_MULT_DOSStub_9a6b {
  strings:
    $key_9a6b = { ce 03 [2] ba 1b [2] fd 19 [2] ba 08 [2] f4 04 [2] f8 0e [2] ef 05 [2] f4 4b [2] c9 }

  condition:
    any of them
}