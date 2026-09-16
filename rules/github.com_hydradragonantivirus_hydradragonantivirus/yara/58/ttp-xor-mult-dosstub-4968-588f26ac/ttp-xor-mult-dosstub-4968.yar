rule TTP_XOR_MULT_DOSStub_4968 {
  strings:
    $key_4968 = { 1d 00 [2] 69 18 [2] 2e 1a [2] 69 0b [2] 27 07 [2] 2b 0d [2] 3c 06 [2] 27 48 [2] 1a }

  condition:
    any of them
}