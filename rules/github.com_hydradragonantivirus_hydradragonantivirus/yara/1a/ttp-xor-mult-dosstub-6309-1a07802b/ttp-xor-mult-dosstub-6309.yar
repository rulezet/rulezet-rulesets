rule TTP_XOR_MULT_DOSStub_6309 {
  strings:
    $key_6309 = { 37 61 [2] 43 79 [2] 04 7b [2] 43 6a [2] 0d 66 [2] 01 6c [2] 16 67 [2] 0d 29 [2] 30 }

  condition:
    any of them
}