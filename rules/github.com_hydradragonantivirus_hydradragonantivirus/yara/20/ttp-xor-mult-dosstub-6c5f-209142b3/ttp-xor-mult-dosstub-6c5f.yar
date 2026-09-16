rule TTP_XOR_MULT_DOSStub_6c5f {
  strings:
    $key_6c5f = { 38 37 [2] 4c 2f [2] 0b 2d [2] 4c 3c [2] 02 30 [2] 0e 3a [2] 19 31 [2] 02 7f [2] 3f }

  condition:
    any of them
}