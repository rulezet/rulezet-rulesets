rule TTP_XOR_MULT_DOSStub_7718 {
  strings:
    $key_7718 = { 23 70 [2] 57 68 [2] 10 6a [2] 57 7b [2] 19 77 [2] 15 7d [2] 02 76 [2] 19 38 [2] 24 }

  condition:
    any of them
}