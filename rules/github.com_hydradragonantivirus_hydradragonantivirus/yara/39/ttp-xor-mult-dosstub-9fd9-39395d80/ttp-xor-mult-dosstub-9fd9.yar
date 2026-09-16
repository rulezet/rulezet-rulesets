rule TTP_XOR_MULT_DOSStub_9fd9 {
  strings:
    $key_9fd9 = { cb b1 [2] bf a9 [2] f8 ab [2] bf ba [2] f1 b6 [2] fd bc [2] ea b7 [2] f1 f9 [2] cc }

  condition:
    any of them
}