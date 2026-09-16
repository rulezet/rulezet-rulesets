rule TTP_XOR_MULT_DOSStub_031c {
  strings:
    $key_031c = { 57 74 [2] 23 6c [2] 64 6e [2] 23 7f [2] 6d 73 [2] 61 79 [2] 76 72 [2] 6d 3c [2] 50 }

  condition:
    any of them
}