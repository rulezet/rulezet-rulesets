rule TTP_XOR_MULT_DOSStub_4520 {
  strings:
    $key_4520 = { 11 48 [2] 65 50 [2] 22 52 [2] 65 43 [2] 2b 4f [2] 27 45 [2] 30 4e [2] 2b 00 [2] 16 }

  condition:
    any of them
}