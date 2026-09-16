rule TTP_XOR_MULT_DOSStub_2562 {
  strings:
    $key_2562 = { 71 0a [2] 05 12 [2] 42 10 [2] 05 01 [2] 4b 0d [2] 47 07 [2] 50 0c [2] 4b 42 [2] 76 }

  condition:
    any of them
}