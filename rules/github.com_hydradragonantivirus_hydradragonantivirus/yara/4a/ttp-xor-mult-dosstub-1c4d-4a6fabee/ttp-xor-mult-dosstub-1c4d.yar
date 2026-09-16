rule TTP_XOR_MULT_DOSStub_1c4d {
  strings:
    $key_1c4d = { 48 25 [2] 3c 3d [2] 7b 3f [2] 3c 2e [2] 72 22 [2] 7e 28 [2] 69 23 [2] 72 6d [2] 4f }

  condition:
    any of them
}