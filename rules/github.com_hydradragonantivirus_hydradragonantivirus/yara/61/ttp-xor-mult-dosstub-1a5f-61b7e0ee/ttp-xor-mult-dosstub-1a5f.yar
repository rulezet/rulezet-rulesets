rule TTP_XOR_MULT_DOSStub_1a5f {
  strings:
    $key_1a5f = { 4e 37 [2] 3a 2f [2] 7d 2d [2] 3a 3c [2] 74 30 [2] 78 3a [2] 6f 31 [2] 74 7f [2] 49 }

  condition:
    any of them
}