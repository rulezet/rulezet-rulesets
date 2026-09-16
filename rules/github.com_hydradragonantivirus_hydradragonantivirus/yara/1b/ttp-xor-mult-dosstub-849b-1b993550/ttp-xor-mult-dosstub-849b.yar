rule TTP_XOR_MULT_DOSStub_849b {
  strings:
    $key_849b = { d0 f3 [2] a4 eb [2] e3 e9 [2] a4 f8 [2] ea f4 [2] e6 fe [2] f1 f5 [2] ea bb [2] d7 }

  condition:
    any of them
}