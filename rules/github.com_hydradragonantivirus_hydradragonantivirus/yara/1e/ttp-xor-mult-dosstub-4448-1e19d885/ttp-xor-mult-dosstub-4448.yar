rule TTP_XOR_MULT_DOSStub_4448 {
  strings:
    $key_4448 = { 10 20 [2] 64 38 [2] 23 3a [2] 64 2b [2] 2a 27 [2] 26 2d [2] 31 26 [2] 2a 68 [2] 17 }

  condition:
    any of them
}