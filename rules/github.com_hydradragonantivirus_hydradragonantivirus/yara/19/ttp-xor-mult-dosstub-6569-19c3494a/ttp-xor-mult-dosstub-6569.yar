rule TTP_XOR_MULT_DOSStub_6569 {
  strings:
    $key_6569 = { 31 01 [2] 45 19 [2] 02 1b [2] 45 0a [2] 0b 06 [2] 07 0c [2] 10 07 [2] 0b 49 [2] 36 }

  condition:
    any of them
}