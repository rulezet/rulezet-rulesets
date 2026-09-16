rule TTP_XOR_MULT_DOSStub_6561 {
  strings:
    $key_6561 = { 31 09 [2] 45 11 [2] 02 13 [2] 45 02 [2] 0b 0e [2] 07 04 [2] 10 0f [2] 0b 41 [2] 36 }

  condition:
    any of them
}