rule TTP_XOR_MULT_DOSStub_0d20 {
  strings:
    $key_0d20 = { 59 48 [2] 2d 50 [2] 6a 52 [2] 2d 43 [2] 63 4f [2] 6f 45 [2] 78 4e [2] 63 00 [2] 5e }

  condition:
    any of them
}