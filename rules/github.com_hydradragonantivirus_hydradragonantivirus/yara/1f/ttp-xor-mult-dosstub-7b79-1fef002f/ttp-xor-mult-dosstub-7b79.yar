rule TTP_XOR_MULT_DOSStub_7b79 {
  strings:
    $key_7b79 = { 2f 11 [2] 5b 09 [2] 1c 0b [2] 5b 1a [2] 15 16 [2] 19 1c [2] 0e 17 [2] 15 59 [2] 28 }

  condition:
    any of them
}