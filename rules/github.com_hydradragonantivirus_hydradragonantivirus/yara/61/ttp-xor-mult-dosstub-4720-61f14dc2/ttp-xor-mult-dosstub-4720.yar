rule TTP_XOR_MULT_DOSStub_4720 {
  strings:
    $key_4720 = { 13 48 [2] 67 50 [2] 20 52 [2] 67 43 [2] 29 4f [2] 25 45 [2] 32 4e [2] 29 00 [2] 14 }

  condition:
    any of them
}