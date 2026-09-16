rule TTP_XOR_MULT_DOSStub_1c1c {
  strings:
    $key_1c1c = { 48 74 [2] 3c 6c [2] 7b 6e [2] 3c 7f [2] 72 73 [2] 7e 79 [2] 69 72 [2] 72 3c [2] 4f }

  condition:
    any of them
}