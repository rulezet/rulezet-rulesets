rule TTP_XOR_MULT_DOSStub_1979 {
  strings:
    $key_1979 = { 4d 11 [2] 39 09 [2] 7e 0b [2] 39 1a [2] 77 16 [2] 7b 1c [2] 6c 17 [2] 77 59 [2] 4a }

  condition:
    any of them
}