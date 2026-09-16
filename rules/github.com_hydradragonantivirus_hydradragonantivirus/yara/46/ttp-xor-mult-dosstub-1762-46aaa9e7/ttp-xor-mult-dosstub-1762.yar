rule TTP_XOR_MULT_DOSStub_1762 {
  strings:
    $key_1762 = { 43 0a [2] 37 12 [2] 70 10 [2] 37 01 [2] 79 0d [2] 75 07 [2] 62 0c [2] 79 42 [2] 44 }

  condition:
    any of them
}