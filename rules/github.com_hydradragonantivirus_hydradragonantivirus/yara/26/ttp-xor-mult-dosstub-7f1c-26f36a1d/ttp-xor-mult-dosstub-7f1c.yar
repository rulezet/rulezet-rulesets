rule TTP_XOR_MULT_DOSStub_7f1c {
  strings:
    $key_7f1c = { 2b 74 [2] 5f 6c [2] 18 6e [2] 5f 7f [2] 11 73 [2] 1d 79 [2] 0a 72 [2] 11 3c [2] 2c }

  condition:
    any of them
}