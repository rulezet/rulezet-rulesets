rule TTP_XOR_MULT_DOSStub_15f8 {
  strings:
    $key_15f8 = { 41 90 [2] 35 88 [2] 72 8a [2] 35 9b [2] 7b 97 [2] 77 9d [2] 60 96 [2] 7b d8 [2] 46 }

  condition:
    any of them
}