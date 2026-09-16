rule TTP_XOR_MULT_DOSStub_5502 {
  strings:
    $key_5502 = { 01 6a [2] 75 72 [2] 32 70 [2] 75 61 [2] 3b 6d [2] 37 67 [2] 20 6c [2] 3b 22 [2] 06 }

  condition:
    any of them
}