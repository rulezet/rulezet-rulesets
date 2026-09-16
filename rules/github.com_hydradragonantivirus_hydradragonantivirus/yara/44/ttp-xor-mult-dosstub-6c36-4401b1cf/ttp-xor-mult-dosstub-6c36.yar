rule TTP_XOR_MULT_DOSStub_6c36 {
  strings:
    $key_6c36 = { 38 5e [2] 4c 46 [2] 0b 44 [2] 4c 55 [2] 02 59 [2] 0e 53 [2] 19 58 [2] 02 16 [2] 3f }

  condition:
    any of them
}