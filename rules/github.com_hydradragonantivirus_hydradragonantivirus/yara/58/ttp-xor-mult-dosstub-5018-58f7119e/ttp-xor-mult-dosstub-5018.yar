rule TTP_XOR_MULT_DOSStub_5018 {
  strings:
    $key_5018 = { 04 70 [2] 70 68 [2] 37 6a [2] 70 7b [2] 3e 77 [2] 32 7d [2] 25 76 [2] 3e 38 [2] 03 }

  condition:
    any of them
}