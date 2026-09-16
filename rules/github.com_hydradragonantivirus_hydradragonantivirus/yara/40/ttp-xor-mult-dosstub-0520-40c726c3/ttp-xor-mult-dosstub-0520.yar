rule TTP_XOR_MULT_DOSStub_0520 {
  strings:
    $key_0520 = { 51 48 [2] 25 50 [2] 62 52 [2] 25 43 [2] 6b 4f [2] 67 45 [2] 70 4e [2] 6b 00 [2] 56 }

  condition:
    any of them
}