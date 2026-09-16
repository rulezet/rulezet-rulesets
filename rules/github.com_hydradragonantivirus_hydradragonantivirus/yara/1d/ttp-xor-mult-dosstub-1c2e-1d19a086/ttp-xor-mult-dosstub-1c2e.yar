rule TTP_XOR_MULT_DOSStub_1c2e {
  strings:
    $key_1c2e = { 48 46 [2] 3c 5e [2] 7b 5c [2] 3c 4d [2] 72 41 [2] 7e 4b [2] 69 40 [2] 72 0e [2] 4f }

  condition:
    any of them
}