rule TTP_XOR_MULT_DOSStub_6059 {
  strings:
    $key_6059 = { 34 31 [2] 40 29 [2] 07 2b [2] 40 3a [2] 0e 36 [2] 02 3c [2] 15 37 [2] 0e 79 [2] 33 }

  condition:
    any of them
}