rule TTP_XOR_MULT_DOSStub_0572 {
  strings:
    $key_0572 = { 51 1a [2] 25 02 [2] 62 00 [2] 25 11 [2] 6b 1d [2] 67 17 [2] 70 1c [2] 6b 52 [2] 56 }

  condition:
    any of them
}