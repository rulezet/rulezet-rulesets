rule TTP_XOR_MULT_DOSStub_9fda {
  strings:
    $key_9fda = { cb b2 [2] bf aa [2] f8 a8 [2] bf b9 [2] f1 b5 [2] fd bf [2] ea b4 [2] f1 fa [2] cc }

  condition:
    any of them
}