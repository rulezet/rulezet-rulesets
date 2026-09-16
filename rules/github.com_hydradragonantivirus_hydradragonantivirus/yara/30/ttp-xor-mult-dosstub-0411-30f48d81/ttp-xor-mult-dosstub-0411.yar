rule TTP_XOR_MULT_DOSStub_0411 {
  strings:
    $key_0411 = { 50 79 [2] 24 61 [2] 63 63 [2] 24 72 [2] 6a 7e [2] 66 74 [2] 71 7f [2] 6a 31 [2] 57 }

  condition:
    any of them
}