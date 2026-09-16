rule TTP_XOR_MULT_DOSStub_1c4e {
  strings:
    $key_1c4e = { 48 26 [2] 3c 3e [2] 7b 3c [2] 3c 2d [2] 72 21 [2] 7e 2b [2] 69 20 [2] 72 6e [2] 4f }

  condition:
    any of them
}