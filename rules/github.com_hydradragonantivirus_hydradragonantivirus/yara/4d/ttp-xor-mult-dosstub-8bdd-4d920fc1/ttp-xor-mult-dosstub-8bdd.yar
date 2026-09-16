rule TTP_XOR_MULT_DOSStub_8bdd {
  strings:
    $key_8bdd = { df b5 [2] ab ad [2] ec af [2] ab be [2] e5 b2 [2] e9 b8 [2] fe b3 [2] e5 fd [2] d8 }

  condition:
    any of them
}