rule TTP_XOR_MULT_DOSStub_5520 {
  strings:
    $key_5520 = { 01 48 [2] 75 50 [2] 32 52 [2] 75 43 [2] 3b 4f [2] 37 45 [2] 20 4e [2] 3b 00 [2] 06 }

  condition:
    any of them
}