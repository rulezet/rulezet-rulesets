rule TTP_XOR_MULT_DOSStub_606f {
  strings:
    $key_606f = { 34 07 [2] 40 1f [2] 07 1d [2] 40 0c [2] 0e 00 [2] 02 0a [2] 15 01 [2] 0e 4f [2] 33 }

  condition:
    any of them
}