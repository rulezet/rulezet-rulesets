rule TTP_XOR_MULT_DOSStub_1975 {
  strings:
    $key_1975 = { 4d 1d [2] 39 05 [2] 7e 07 [2] 39 16 [2] 77 1a [2] 7b 10 [2] 6c 1b [2] 77 55 [2] 4a }

  condition:
    any of them
}