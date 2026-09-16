rule TTP_XOR_MULT_DOSStub_1c0c {
  strings:
    $key_1c0c = { 48 64 [2] 3c 7c [2] 7b 7e [2] 3c 6f [2] 72 63 [2] 7e 69 [2] 69 62 [2] 72 2c [2] 4f }

  condition:
    any of them
}