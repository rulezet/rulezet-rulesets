rule TTP_XOR_MULT_DOSStub_1709 {
  strings:
    $key_1709 = { 43 61 [2] 37 79 [2] 70 7b [2] 37 6a [2] 79 66 [2] 75 6c [2] 62 67 [2] 79 29 [2] 44 }

  condition:
    any of them
}