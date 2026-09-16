rule TTP_XOR_MULT_DOSStub_1504 {
  strings:
    $key_1504 = { 41 6c [2] 35 74 [2] 72 76 [2] 35 67 [2] 7b 6b [2] 77 61 [2] 60 6a [2] 7b 24 [2] 46 }

  condition:
    any of them
}