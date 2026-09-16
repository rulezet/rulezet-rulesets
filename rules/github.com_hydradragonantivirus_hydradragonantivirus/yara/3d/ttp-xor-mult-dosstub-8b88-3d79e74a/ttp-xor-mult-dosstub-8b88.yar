rule TTP_XOR_MULT_DOSStub_8b88 {
  strings:
    $key_8b88 = { df e0 [2] ab f8 [2] ec fa [2] ab eb [2] e5 e7 [2] e9 ed [2] fe e6 [2] e5 a8 [2] d8 }

  condition:
    any of them
}