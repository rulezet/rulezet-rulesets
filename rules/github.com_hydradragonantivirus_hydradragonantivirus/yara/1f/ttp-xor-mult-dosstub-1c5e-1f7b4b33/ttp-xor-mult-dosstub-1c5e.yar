rule TTP_XOR_MULT_DOSStub_1c5e {
  strings:
    $key_1c5e = { 48 36 [2] 3c 2e [2] 7b 2c [2] 3c 3d [2] 72 31 [2] 7e 3b [2] 69 30 [2] 72 7e [2] 4f }

  condition:
    any of them
}