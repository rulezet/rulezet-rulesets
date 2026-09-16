rule TTP_XOR_MULT_DOSStub_4002 {
  strings:
    $key_4002 = { 14 6a [2] 60 72 [2] 27 70 [2] 60 61 [2] 2e 6d [2] 22 67 [2] 35 6c [2] 2e 22 [2] 13 }

  condition:
    any of them
}