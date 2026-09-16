rule TTP_XOR_MULT_DOSStub_3b59 {
  strings:
    $key_3b59 = { 6f 31 [2] 1b 29 [2] 5c 2b [2] 1b 3a [2] 55 36 [2] 59 3c [2] 4e 37 [2] 55 79 [2] 68 }

  condition:
    any of them
}