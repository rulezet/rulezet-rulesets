rule TTP_XOR_MULT_DOSStub_8b8d {
  strings:
    $key_8b8d = { df e5 [2] ab fd [2] ec ff [2] ab ee [2] e5 e2 [2] e9 e8 [2] fe e3 [2] e5 ad [2] d8 }

  condition:
    any of them
}