rule TTP_XOR_MULT_DOSStub_603a {
  strings:
    $key_603a = { 34 52 [2] 40 4a [2] 07 48 [2] 40 59 [2] 0e 55 [2] 02 5f [2] 15 54 [2] 0e 1a [2] 33 }

  condition:
    any of them
}