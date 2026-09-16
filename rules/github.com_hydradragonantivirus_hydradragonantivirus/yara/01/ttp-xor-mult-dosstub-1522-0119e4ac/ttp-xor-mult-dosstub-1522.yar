rule TTP_XOR_MULT_DOSStub_1522 {
  strings:
    $key_1522 = { 41 4a [2] 35 52 [2] 72 50 [2] 35 41 [2] 7b 4d [2] 77 47 [2] 60 4c [2] 7b 02 [2] 46 }

  condition:
    any of them
}