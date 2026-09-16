rule TTP_XOR_MULT_DOSStub_3b68 {
  strings:
    $key_3b68 = { 6f 00 [2] 1b 18 [2] 5c 1a [2] 1b 0b [2] 55 07 [2] 59 0d [2] 4e 06 [2] 55 48 [2] 68 }

  condition:
    any of them
}