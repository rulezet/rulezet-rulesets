rule TTP_XOR_MULT_DOSStub_8bdc {
  strings:
    $key_8bdc = { df b4 [2] ab ac [2] ec ae [2] ab bf [2] e5 b3 [2] e9 b9 [2] fe b2 [2] e5 fc [2] d8 }

  condition:
    any of them
}