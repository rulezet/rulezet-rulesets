rule TTP_XOR_MULT_DOSStub_6c30 {
  strings:
    $key_6c30 = { 38 58 [2] 4c 40 [2] 0b 42 [2] 4c 53 [2] 02 5f [2] 0e 55 [2] 19 5e [2] 02 10 [2] 3f }

  condition:
    any of them
}