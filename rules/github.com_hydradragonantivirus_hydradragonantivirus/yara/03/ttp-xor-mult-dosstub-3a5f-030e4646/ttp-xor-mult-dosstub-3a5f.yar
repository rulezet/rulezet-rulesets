rule TTP_XOR_MULT_DOSStub_3a5f {
  strings:
    $key_3a5f = { 6e 37 [2] 1a 2f [2] 5d 2d [2] 1a 3c [2] 54 30 [2] 58 3a [2] 4f 31 [2] 54 7f [2] 69 }

  condition:
    any of them
}