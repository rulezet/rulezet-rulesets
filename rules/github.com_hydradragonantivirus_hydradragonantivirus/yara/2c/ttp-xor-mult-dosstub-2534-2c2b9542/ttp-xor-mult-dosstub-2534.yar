rule TTP_XOR_MULT_DOSStub_2534 {
  strings:
    $key_2534 = { 71 5c [2] 05 44 [2] 42 46 [2] 05 57 [2] 4b 5b [2] 47 51 [2] 50 5a [2] 4b 14 [2] 76 }

  condition:
    any of them
}