rule TTP_XOR_MULT_DOSStub_4629 {
  strings:
    $key_4629 = { 12 41 [2] 66 59 [2] 21 5b [2] 66 4a [2] 28 46 [2] 24 4c [2] 33 47 [2] 28 09 [2] 15 }

  condition:
    any of them
}