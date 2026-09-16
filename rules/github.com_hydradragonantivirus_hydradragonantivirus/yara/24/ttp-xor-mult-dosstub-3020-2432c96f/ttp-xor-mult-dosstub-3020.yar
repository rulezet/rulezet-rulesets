rule TTP_XOR_MULT_DOSStub_3020 {
  strings:
    $key_3020 = { 64 48 [2] 10 50 [2] 57 52 [2] 10 43 [2] 5e 4f [2] 52 45 [2] 45 4e [2] 5e 00 [2] 63 }

  condition:
    any of them
}