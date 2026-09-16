rule TTP_XOR_MULT_DOSStub_601c {
  strings:
    $key_601c = { 34 74 [2] 40 6c [2] 07 6e [2] 40 7f [2] 0e 73 [2] 02 79 [2] 15 72 [2] 0e 3c [2] 33 }

  condition:
    any of them
}