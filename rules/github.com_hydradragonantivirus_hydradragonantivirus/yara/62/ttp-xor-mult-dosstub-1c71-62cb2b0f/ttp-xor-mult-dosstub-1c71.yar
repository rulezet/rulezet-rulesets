rule TTP_XOR_MULT_DOSStub_1c71 {
  strings:
    $key_1c71 = { 48 19 [2] 3c 01 [2] 7b 03 [2] 3c 12 [2] 72 1e [2] 7e 14 [2] 69 1f [2] 72 51 [2] 4f }

  condition:
    any of them
}