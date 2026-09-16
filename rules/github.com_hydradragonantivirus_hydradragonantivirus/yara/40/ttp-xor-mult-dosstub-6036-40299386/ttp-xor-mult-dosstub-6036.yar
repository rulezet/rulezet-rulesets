rule TTP_XOR_MULT_DOSStub_6036 {
  strings:
    $key_6036 = { 34 5e [2] 40 46 [2] 07 44 [2] 40 55 [2] 0e 59 [2] 02 53 [2] 15 58 [2] 0e 16 [2] 33 }

  condition:
    any of them
}