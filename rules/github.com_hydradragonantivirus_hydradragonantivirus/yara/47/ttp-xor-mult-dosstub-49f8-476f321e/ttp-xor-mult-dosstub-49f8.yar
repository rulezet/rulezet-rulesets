rule TTP_XOR_MULT_DOSStub_49f8 {
  strings:
    $key_49f8 = { 1d 90 [2] 69 88 [2] 2e 8a [2] 69 9b [2] 27 97 [2] 2b 9d [2] 3c 96 [2] 27 d8 [2] 1a }

  condition:
    any of them
}