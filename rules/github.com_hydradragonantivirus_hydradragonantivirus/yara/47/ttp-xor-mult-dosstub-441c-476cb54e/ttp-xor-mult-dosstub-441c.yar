rule TTP_XOR_MULT_DOSStub_441c {
  strings:
    $key_441c = { 10 74 [2] 64 6c [2] 23 6e [2] 64 7f [2] 2a 73 [2] 26 79 [2] 31 72 [2] 2a 3c [2] 17 }

  condition:
    any of them
}