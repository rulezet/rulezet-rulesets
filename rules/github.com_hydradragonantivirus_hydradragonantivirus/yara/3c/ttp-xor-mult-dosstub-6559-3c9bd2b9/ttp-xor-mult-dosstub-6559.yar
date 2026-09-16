rule TTP_XOR_MULT_DOSStub_6559 {
  strings:
    $key_6559 = { 31 31 [2] 45 29 [2] 02 2b [2] 45 3a [2] 0b 36 [2] 07 3c [2] 10 37 [2] 0b 79 [2] 36 }

  condition:
    any of them
}