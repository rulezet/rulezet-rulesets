rule TTP_XOR_MULT_DOSStub_4445 {
  strings:
    $key_4445 = { 10 2d [2] 64 35 [2] 23 37 [2] 64 26 [2] 2a 2a [2] 26 20 [2] 31 2b [2] 2a 65 [2] 17 }

  condition:
    any of them
}