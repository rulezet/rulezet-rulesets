rule TTP_XOR_MULT_DOSStub_6c11 {
  strings:
    $key_6c11 = { 38 79 [2] 4c 61 [2] 0b 63 [2] 4c 72 [2] 02 7e [2] 0e 74 [2] 19 7f [2] 02 31 [2] 3f }

  condition:
    any of them
}