rule TTP_XOR_MULT_DOSStub_8d58 {
  strings:
    $key_8d58 = { d9 30 [2] ad 28 [2] ea 2a [2] ad 3b [2] e3 37 [2] ef 3d [2] f8 36 [2] e3 78 [2] de }

  condition:
    any of them
}