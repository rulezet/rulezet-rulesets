rule TTP_XOR_MULT_DOSStub_4f1c {
  strings:
    $key_4f1c = { 1b 74 [2] 6f 6c [2] 28 6e [2] 6f 7f [2] 21 73 [2] 2d 79 [2] 3a 72 [2] 21 3c [2] 1c }

  condition:
    any of them
}