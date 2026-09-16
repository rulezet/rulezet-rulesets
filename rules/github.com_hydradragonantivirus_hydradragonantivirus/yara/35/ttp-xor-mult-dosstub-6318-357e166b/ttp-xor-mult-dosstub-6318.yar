rule TTP_XOR_MULT_DOSStub_6318 {
  strings:
    $key_6318 = { 37 70 [2] 43 68 [2] 04 6a [2] 43 7b [2] 0d 77 [2] 01 7d [2] 16 76 [2] 0d 38 [2] 30 }

  condition:
    any of them
}