rule TTP_XOR_MULT_DOSStub_1027 {
  strings:
    $key_1027 = { 44 4f [2] 30 57 [2] 77 55 [2] 30 44 [2] 7e 48 [2] 72 42 [2] 65 49 [2] 7e 07 [2] 43 }

  condition:
    any of them
}