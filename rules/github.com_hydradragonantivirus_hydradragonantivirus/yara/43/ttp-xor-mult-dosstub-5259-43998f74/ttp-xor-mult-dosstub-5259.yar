rule TTP_XOR_MULT_DOSStub_5259 {
  strings:
    $key_5259 = { 06 31 [2] 72 29 [2] 35 2b [2] 72 3a [2] 3c 36 [2] 30 3c [2] 27 37 [2] 3c 79 [2] 01 }

  condition:
    any of them
}