rule TTP_XOR_MULT_DOSStub_0b59 {
  strings:
    $key_0b59 = { 5f 31 [2] 2b 29 [2] 6c 2b [2] 2b 3a [2] 65 36 [2] 69 3c [2] 7e 37 [2] 65 79 [2] 58 }

  condition:
    any of them
}