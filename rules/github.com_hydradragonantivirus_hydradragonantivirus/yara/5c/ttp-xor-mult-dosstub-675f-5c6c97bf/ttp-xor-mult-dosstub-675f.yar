rule TTP_XOR_MULT_DOSStub_675f {
  strings:
    $key_675f = { 33 37 [2] 47 2f [2] 00 2d [2] 47 3c [2] 09 30 [2] 05 3a [2] 12 31 [2] 09 7f [2] 34 }

  condition:
    any of them
}