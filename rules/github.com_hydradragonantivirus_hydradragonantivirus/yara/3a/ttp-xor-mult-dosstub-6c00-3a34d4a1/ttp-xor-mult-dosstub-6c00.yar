rule TTP_XOR_MULT_DOSStub_6c00 {
  strings:
    $key_6c00 = { 38 68 [2] 4c 70 [2] 0b 72 [2] 4c 63 [2] 02 6f [2] 0e 65 [2] 19 6e [2] 02 20 [2] 3f }

  condition:
    any of them
}