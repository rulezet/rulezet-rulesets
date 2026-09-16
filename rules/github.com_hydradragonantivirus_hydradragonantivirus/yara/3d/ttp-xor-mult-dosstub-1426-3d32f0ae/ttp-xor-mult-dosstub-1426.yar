rule TTP_XOR_MULT_DOSStub_1426 {
  strings:
    $key_1426 = { 40 4e [2] 34 56 [2] 73 54 [2] 34 45 [2] 7a 49 [2] 76 43 [2] 61 48 [2] 7a 06 [2] 47 }

  condition:
    any of them
}