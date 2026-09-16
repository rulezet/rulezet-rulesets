rule TTP_XOR_MULT_DOSStub_1b59 {
  strings:
    $key_1b59 = { 4f 31 [2] 3b 29 [2] 7c 2b [2] 3b 3a [2] 75 36 [2] 79 3c [2] 6e 37 [2] 75 79 [2] 48 }

  condition:
    any of them
}