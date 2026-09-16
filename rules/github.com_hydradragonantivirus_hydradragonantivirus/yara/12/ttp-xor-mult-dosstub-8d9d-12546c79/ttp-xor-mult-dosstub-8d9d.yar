rule TTP_XOR_MULT_DOSStub_8d9d {
  strings:
    $key_8d9d = { d9 f5 [2] ad ed [2] ea ef [2] ad fe [2] e3 f2 [2] ef f8 [2] f8 f3 [2] e3 bd [2] de }

  condition:
    any of them
}