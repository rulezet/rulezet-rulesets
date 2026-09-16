rule TTP_XOR_MULT_DOSStub_3978 {
  strings:
    $key_3978 = { 6d 10 [2] 19 08 [2] 5e 0a [2] 19 1b [2] 57 17 [2] 5b 1d [2] 4c 16 [2] 57 58 [2] 6a }

  condition:
    any of them
}