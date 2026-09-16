rule TTP_XOR_MULT_DOSStub_4b1c {
  strings:
    $key_4b1c = { 1f 74 [2] 6b 6c [2] 2c 6e [2] 6b 7f [2] 25 73 [2] 29 79 [2] 3e 72 [2] 25 3c [2] 18 }

  condition:
    any of them
}