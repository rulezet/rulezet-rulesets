rule TTP_XOR_MULT_DOSStub_9fd6 {
  strings:
    $key_9fd6 = { cb be [2] bf a6 [2] f8 a4 [2] bf b5 [2] f1 b9 [2] fd b3 [2] ea b8 [2] f1 f6 [2] cc }

  condition:
    any of them
}