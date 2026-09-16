rule TTP_XOR_MULT_DOSStub_4759 {
  strings:
    $key_4759 = { 13 31 [2] 67 29 [2] 20 2b [2] 67 3a [2] 29 36 [2] 25 3c [2] 32 37 [2] 29 79 [2] 14 }

  condition:
    any of them
}