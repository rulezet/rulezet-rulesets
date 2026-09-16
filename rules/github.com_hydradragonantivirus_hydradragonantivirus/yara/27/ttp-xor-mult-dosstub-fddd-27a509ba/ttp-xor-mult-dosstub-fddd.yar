rule TTP_XOR_MULT_DOSStub_fddd {
  strings:
    $key_fddd = { a9 b5 [2] dd ad [2] 9a af [2] dd be [2] 93 b2 [2] 9f b8 [2] 88 b3 [2] 93 fd [2] ae }

  condition:
    any of them
}