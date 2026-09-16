rule TTP_XOR_MULT_DOSStub_6532 {
  strings:
    $key_6532 = { 31 5a [2] 45 42 [2] 02 40 [2] 45 51 [2] 0b 5d [2] 07 57 [2] 10 5c [2] 0b 12 [2] 36 }

  condition:
    any of them
}