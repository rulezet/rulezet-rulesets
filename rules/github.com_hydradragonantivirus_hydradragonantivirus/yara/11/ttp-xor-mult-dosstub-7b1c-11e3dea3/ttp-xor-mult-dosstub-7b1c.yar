rule TTP_XOR_MULT_DOSStub_7b1c {
  strings:
    $key_7b1c = { 2f 74 [2] 5b 6c [2] 1c 6e [2] 5b 7f [2] 15 73 [2] 19 79 [2] 0e 72 [2] 15 3c [2] 28 }

  condition:
    any of them
}