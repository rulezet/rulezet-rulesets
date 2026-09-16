rule TTP_XOR_MULT_DOSStub_711c {
  strings:
    $key_711c = { 25 74 [2] 51 6c [2] 16 6e [2] 51 7f [2] 1f 73 [2] 13 79 [2] 04 72 [2] 1f 3c [2] 22 }

  condition:
    any of them
}