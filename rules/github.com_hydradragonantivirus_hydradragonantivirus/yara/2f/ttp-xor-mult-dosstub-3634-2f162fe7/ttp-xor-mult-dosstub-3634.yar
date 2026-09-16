rule TTP_XOR_MULT_DOSStub_3634 {
  strings:
    $key_3634 = { 62 5c [2] 16 44 [2] 51 46 [2] 16 57 [2] 58 5b [2] 54 51 [2] 43 5a [2] 58 14 [2] 65 }

  condition:
    any of them
}