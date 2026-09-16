rule TTP_XOR_MULT_DOSStub_7a5f {
  strings:
    $key_7a5f = { 2e 37 [2] 5a 2f [2] 1d 2d [2] 5a 3c [2] 14 30 [2] 18 3a [2] 0f 31 [2] 14 7f [2] 29 }

  condition:
    any of them
}