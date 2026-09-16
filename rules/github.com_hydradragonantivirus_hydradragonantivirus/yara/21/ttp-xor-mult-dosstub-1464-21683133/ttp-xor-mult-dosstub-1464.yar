rule TTP_XOR_MULT_DOSStub_1464 {
  strings:
    $key_1464 = { 40 0c [2] 34 14 [2] 73 16 [2] 34 07 [2] 7a 0b [2] 76 01 [2] 61 0a [2] 7a 44 [2] 47 }

  condition:
    any of them
}