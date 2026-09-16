rule TTP_XOR_MULT_DOSStub_3975 {
  strings:
    $key_3975 = { 6d 1d [2] 19 05 [2] 5e 07 [2] 19 16 [2] 57 1a [2] 5b 10 [2] 4c 1b [2] 57 55 [2] 6a }

  condition:
    any of them
}