rule TTP_XOR_MULT_DOSStub_405d {
  strings:
    $key_405d = { 14 35 [2] 60 2d [2] 27 2f [2] 60 3e [2] 2e 32 [2] 22 38 [2] 35 33 [2] 2e 7d [2] 13 }

  condition:
    any of them
}