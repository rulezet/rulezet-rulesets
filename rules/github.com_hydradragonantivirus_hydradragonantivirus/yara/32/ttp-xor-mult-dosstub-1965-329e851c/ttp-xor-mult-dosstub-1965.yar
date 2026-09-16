rule TTP_XOR_MULT_DOSStub_1965 {
  strings:
    $key_1965 = { 4d 0d [2] 39 15 [2] 7e 17 [2] 39 06 [2] 77 0a [2] 7b 00 [2] 6c 0b [2] 77 45 [2] 4a }

  condition:
    any of them
}