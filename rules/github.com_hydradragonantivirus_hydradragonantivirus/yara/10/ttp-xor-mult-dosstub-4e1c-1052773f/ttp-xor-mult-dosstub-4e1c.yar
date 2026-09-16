rule TTP_XOR_MULT_DOSStub_4e1c {
  strings:
    $key_4e1c = { 1a 74 [2] 6e 6c [2] 29 6e [2] 6e 7f [2] 20 73 [2] 2c 79 [2] 3b 72 [2] 20 3c [2] 1d }

  condition:
    any of them
}