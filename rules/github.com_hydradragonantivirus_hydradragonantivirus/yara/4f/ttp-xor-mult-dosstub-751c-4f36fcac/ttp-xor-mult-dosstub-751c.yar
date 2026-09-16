rule TTP_XOR_MULT_DOSStub_751c {
  strings:
    $key_751c = { 21 74 [2] 55 6c [2] 12 6e [2] 55 7f [2] 1b 73 [2] 17 79 [2] 00 72 [2] 1b 3c [2] 26 }

  condition:
    any of them
}