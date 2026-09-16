rule TTP_XOR_MULT_DOSStub_db9d {
  strings:
    $key_db9d = { 8f f5 [2] fb ed [2] bc ef [2] fb fe [2] b5 f2 [2] b9 f8 [2] ae f3 [2] b5 bd [2] 88 }

  condition:
    any of them
}