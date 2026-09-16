rule TTP_XOR_MULT_DOSStub_1c7e {
  strings:
    $key_1c7e = { 48 16 [2] 3c 0e [2] 7b 0c [2] 3c 1d [2] 72 11 [2] 7e 1b [2] 69 10 [2] 72 5e [2] 4f }

  condition:
    any of them
}