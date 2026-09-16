rule TTP_XOR_MULT_DOSStub_771c {
  strings:
    $key_771c = { 23 74 [2] 57 6c [2] 10 6e [2] 57 7f [2] 19 73 [2] 15 79 [2] 02 72 [2] 19 3c [2] 24 }

  condition:
    any of them
}