rule TTP_XOR_MULT_DOSStub_6279 {
  strings:
    $key_6279 = { 36 11 [2] 42 09 [2] 05 0b [2] 42 1a [2] 0c 16 [2] 00 1c [2] 17 17 [2] 0c 59 [2] 31 }

  condition:
    any of them
}