rule TTP_XOR_MULT_DOSStub_1402 {
  strings:
    $key_1402 = { 40 6a [2] 34 72 [2] 73 70 [2] 34 61 [2] 7a 6d [2] 76 67 [2] 61 6c [2] 7a 22 [2] 47 }

  condition:
    any of them
}