rule TTP_XOR_MULT_DOSStub_4502 {
  strings:
    $key_4502 = { 11 6a [2] 65 72 [2] 22 70 [2] 65 61 [2] 2b 6d [2] 27 67 [2] 30 6c [2] 2b 22 [2] 16 }

  condition:
    any of them
}