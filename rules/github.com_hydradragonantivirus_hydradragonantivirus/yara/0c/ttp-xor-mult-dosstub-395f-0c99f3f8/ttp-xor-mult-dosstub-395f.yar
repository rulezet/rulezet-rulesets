rule TTP_XOR_MULT_DOSStub_395f {
  strings:
    $key_395f = { 6d 37 [2] 19 2f [2] 5e 2d [2] 19 3c [2] 57 30 [2] 5b 3a [2] 4c 31 [2] 57 7f [2] 6a }

  condition:
    any of them
}