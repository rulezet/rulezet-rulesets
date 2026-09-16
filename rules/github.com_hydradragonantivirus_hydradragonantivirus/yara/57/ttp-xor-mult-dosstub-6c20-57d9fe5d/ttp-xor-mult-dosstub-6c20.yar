rule TTP_XOR_MULT_DOSStub_6c20 {
  strings:
    $key_6c20 = { 38 48 [2] 4c 50 [2] 0b 52 [2] 4c 43 [2] 02 4f [2] 0e 45 [2] 19 4e [2] 02 00 [2] 3f }

  condition:
    any of them
}