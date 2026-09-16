rule TTP_XOR_MULT_DOSStub_651c {
  strings:
    $key_651c = { 31 74 [2] 45 6c [2] 02 6e [2] 45 7f [2] 0b 73 [2] 07 79 [2] 10 72 [2] 0b 3c [2] 36 }

  condition:
    any of them
}