rule TTP_XOR_MULT_DOSStub_3718 {
  strings:
    $key_3718 = { 63 70 [2] 17 68 [2] 50 6a [2] 17 7b [2] 59 77 [2] 55 7d [2] 42 76 [2] 59 38 [2] 64 }

  condition:
    any of them
}