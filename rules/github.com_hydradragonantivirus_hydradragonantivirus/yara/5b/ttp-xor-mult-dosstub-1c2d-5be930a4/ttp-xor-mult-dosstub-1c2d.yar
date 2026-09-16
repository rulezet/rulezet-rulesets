rule TTP_XOR_MULT_DOSStub_1c2d {
  strings:
    $key_1c2d = { 48 45 [2] 3c 5d [2] 7b 5f [2] 3c 4e [2] 72 42 [2] 7e 48 [2] 69 43 [2] 72 0d [2] 4f }

  condition:
    any of them
}