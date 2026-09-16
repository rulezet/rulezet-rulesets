rule TTP_XOR_MULT_DOSStub_6572 {
  strings:
    $key_6572 = { 31 1a [2] 45 02 [2] 02 00 [2] 45 11 [2] 0b 1d [2] 07 17 [2] 10 1c [2] 0b 52 [2] 36 }

  condition:
    any of them
}