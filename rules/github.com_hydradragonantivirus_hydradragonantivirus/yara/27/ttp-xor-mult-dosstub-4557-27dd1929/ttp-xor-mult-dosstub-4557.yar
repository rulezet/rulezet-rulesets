rule TTP_XOR_MULT_DOSStub_4557 {
  strings:
    $key_4557 = { 11 3f [2] 65 27 [2] 22 25 [2] 65 34 [2] 2b 38 [2] 27 32 [2] 30 39 [2] 2b 77 [2] 16 }

  condition:
    any of them
}