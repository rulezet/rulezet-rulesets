rule TTP_XOR_MULT_DOSStub_631c {
  strings:
    $key_631c = { 37 74 [2] 43 6c [2] 04 6e [2] 43 7f [2] 0d 73 [2] 01 79 [2] 16 72 [2] 0d 3c [2] 30 }

  condition:
    any of them
}