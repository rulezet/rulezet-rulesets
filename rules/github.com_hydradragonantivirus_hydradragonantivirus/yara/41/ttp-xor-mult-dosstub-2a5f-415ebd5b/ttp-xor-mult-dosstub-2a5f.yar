rule TTP_XOR_MULT_DOSStub_2a5f {
  strings:
    $key_2a5f = { 7e 37 [2] 0a 2f [2] 4d 2d [2] 0a 3c [2] 44 30 [2] 48 3a [2] 5f 31 [2] 44 7f [2] 79 }

  condition:
    any of them
}