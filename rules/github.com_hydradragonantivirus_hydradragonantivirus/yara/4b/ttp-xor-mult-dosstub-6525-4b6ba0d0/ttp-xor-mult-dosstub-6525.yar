rule TTP_XOR_MULT_DOSStub_6525 {
  strings:
    $key_6525 = { 31 4d [2] 45 55 [2] 02 57 [2] 45 46 [2] 0b 4a [2] 07 40 [2] 10 4b [2] 0b 05 [2] 36 }

  condition:
    any of them
}