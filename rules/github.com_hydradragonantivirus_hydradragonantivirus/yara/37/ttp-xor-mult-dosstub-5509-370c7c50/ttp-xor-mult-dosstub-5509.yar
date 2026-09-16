rule TTP_XOR_MULT_DOSStub_5509 {
  strings:
    $key_5509 = { 01 61 [2] 75 79 [2] 32 7b [2] 75 6a [2] 3b 66 [2] 37 6c [2] 20 67 [2] 3b 29 [2] 06 }

  condition:
    any of them
}