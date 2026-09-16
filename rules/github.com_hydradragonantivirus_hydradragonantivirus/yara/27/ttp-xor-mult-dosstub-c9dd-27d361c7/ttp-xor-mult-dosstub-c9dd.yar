rule TTP_XOR_MULT_DOSStub_c9dd {
  strings:
    $key_c9dd = { 9d b5 [2] e9 ad [2] ae af [2] e9 be [2] a7 b2 [2] ab b8 [2] bc b3 [2] a7 fd [2] 9a }

  condition:
    any of them
}