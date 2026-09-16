rule TTP_XOR_MULT_DOSStub_4024 {
  strings:
    $key_4024 = { 14 4c [2] 60 54 [2] 27 56 [2] 60 47 [2] 2e 4b [2] 22 41 [2] 35 4a [2] 2e 04 [2] 13 }

  condition:
    any of them
}