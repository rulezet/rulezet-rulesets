rule TTP_XOR_MULT_DOSStub_8bcb {
  strings:
    $key_8bcb = { df a3 [2] ab bb [2] ec b9 [2] ab a8 [2] e5 a4 [2] e9 ae [2] fe a5 [2] e5 eb [2] d8 }

  condition:
    any of them
}