rule TTP_XOR_MULT_DOSStub_0734 {
  strings:
    $key_0734 = { 53 5c [2] 27 44 [2] 60 46 [2] 27 57 [2] 69 5b [2] 65 51 [2] 72 5a [2] 69 14 [2] 54 }

  condition:
    any of them
}