rule TTP_XOR_MULT_DOSStub_2518 {
  strings:
    $key_2518 = { 71 70 [2] 05 68 [2] 42 6a [2] 05 7b [2] 4b 77 [2] 47 7d [2] 50 76 [2] 4b 38 [2] 76 }

  condition:
    any of them
}