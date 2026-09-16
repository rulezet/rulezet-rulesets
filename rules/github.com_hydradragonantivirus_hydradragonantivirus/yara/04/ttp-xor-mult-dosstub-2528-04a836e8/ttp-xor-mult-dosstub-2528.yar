rule TTP_XOR_MULT_DOSStub_2528 {
  strings:
    $key_2528 = { 71 40 [2] 05 58 [2] 42 5a [2] 05 4b [2] 4b 47 [2] 47 4d [2] 50 46 [2] 4b 08 [2] 76 }

  condition:
    any of them
}