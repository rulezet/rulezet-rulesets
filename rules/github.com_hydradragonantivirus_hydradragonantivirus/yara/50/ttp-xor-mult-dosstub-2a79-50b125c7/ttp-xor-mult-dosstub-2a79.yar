rule TTP_XOR_MULT_DOSStub_2a79 {
  strings:
    $key_2a79 = { 7e 11 [2] 0a 09 [2] 4d 0b [2] 0a 1a [2] 44 16 [2] 48 1c [2] 5f 17 [2] 44 59 [2] 79 }

  condition:
    any of them
}