rule TTP_XOR_MULT_DOSStub_4b68 {
  strings:
    $key_4b68 = { 1f 00 [2] 6b 18 [2] 2c 1a [2] 6b 0b [2] 25 07 [2] 29 0d [2] 3e 06 [2] 25 48 [2] 18 }

  condition:
    any of them
}