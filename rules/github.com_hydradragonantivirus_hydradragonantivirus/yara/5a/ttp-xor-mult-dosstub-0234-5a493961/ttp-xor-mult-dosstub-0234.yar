rule TTP_XOR_MULT_DOSStub_0234 {
  strings:
    $key_0234 = { 56 5c [2] 22 44 [2] 65 46 [2] 22 57 [2] 6c 5b [2] 60 51 [2] 77 5a [2] 6c 14 [2] 51 }

  condition:
    any of them
}