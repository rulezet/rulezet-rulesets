rule TTP_XOR_MULT_DOSStub_6245 {
  strings:
    $key_6245 = { 36 2d [2] 42 35 [2] 05 37 [2] 42 26 [2] 0c 2a [2] 00 20 [2] 17 2b [2] 0c 65 [2] 31 }

  condition:
    any of them
}