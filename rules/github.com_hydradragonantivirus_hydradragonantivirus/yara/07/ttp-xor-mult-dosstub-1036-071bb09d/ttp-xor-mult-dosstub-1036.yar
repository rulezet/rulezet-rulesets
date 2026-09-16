rule TTP_XOR_MULT_DOSStub_1036 {
  strings:
    $key_1036 = { 44 5e [2] 30 46 [2] 77 44 [2] 30 55 [2] 7e 59 [2] 72 53 [2] 65 58 [2] 7e 16 [2] 43 }

  condition:
    any of them
}