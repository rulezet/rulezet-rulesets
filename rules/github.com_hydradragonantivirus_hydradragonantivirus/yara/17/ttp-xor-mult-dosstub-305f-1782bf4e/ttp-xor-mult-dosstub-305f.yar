rule TTP_XOR_MULT_DOSStub_305f {
  strings:
    $key_305f = { 64 37 [2] 10 2f [2] 57 2d [2] 10 3c [2] 5e 30 [2] 52 3a [2] 45 31 [2] 5e 7f [2] 63 }

  condition:
    any of them
}