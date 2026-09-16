rule TTP_XOR_MULT_DOSStub_0739 {
  strings:
    $key_0739 = { 53 51 [2] 27 49 [2] 60 4b [2] 27 5a [2] 69 56 [2] 65 5c [2] 72 57 [2] 69 19 [2] 54 }

  condition:
    any of them
}