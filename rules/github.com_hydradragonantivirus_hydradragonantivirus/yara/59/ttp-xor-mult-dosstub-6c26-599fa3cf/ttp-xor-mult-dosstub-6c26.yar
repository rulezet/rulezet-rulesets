rule TTP_XOR_MULT_DOSStub_6c26 {
  strings:
    $key_6c26 = { 38 4e [2] 4c 56 [2] 0b 54 [2] 4c 45 [2] 02 49 [2] 0e 43 [2] 19 48 [2] 02 06 [2] 3f }

  condition:
    any of them
}