rule TTP_XOR_MULT_DOSStub_4709 {
  strings:
    $key_4709 = { 13 61 [2] 67 79 [2] 20 7b [2] 67 6a [2] 29 66 [2] 25 6c [2] 32 67 [2] 29 29 [2] 14 }

  condition:
    any of them
}