rule TTP_XOR_MULT_DOSStub_201c {
  strings:
    $key_201c = { 74 74 [2] 00 6c [2] 47 6e [2] 00 7f [2] 4e 73 [2] 42 79 [2] 55 72 [2] 4e 3c [2] 73 }

  condition:
    any of them
}