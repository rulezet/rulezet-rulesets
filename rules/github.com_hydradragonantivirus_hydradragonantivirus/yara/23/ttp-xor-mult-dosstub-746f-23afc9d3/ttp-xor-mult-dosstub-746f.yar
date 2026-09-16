rule TTP_XOR_MULT_DOSStub_746f {
  strings:
    $key_746f = { 20 07 [2] 54 1f [2] 13 1d [2] 54 0c [2] 1a 00 [2] 16 0a [2] 01 01 [2] 1a 4f [2] 27 }

  condition:
    any of them
}