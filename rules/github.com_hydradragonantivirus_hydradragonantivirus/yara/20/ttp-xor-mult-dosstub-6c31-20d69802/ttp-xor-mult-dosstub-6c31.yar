rule TTP_XOR_MULT_DOSStub_6c31 {
  strings:
    $key_6c31 = { 38 59 [2] 4c 41 [2] 0b 43 [2] 4c 52 [2] 02 5e [2] 0e 54 [2] 19 5f [2] 02 11 [2] 3f }

  condition:
    any of them
}