rule TTP_XOR_MULT_DOSStub_6527 {
  strings:
    $key_6527 = { 31 4f [2] 45 57 [2] 02 55 [2] 45 44 [2] 0b 48 [2] 07 42 [2] 10 49 [2] 0b 07 [2] 36 }

  condition:
    any of them
}