rule TTP_XOR_MULT_DOSStub_0709 {
  strings:
    $key_0709 = { 53 61 [2] 27 79 [2] 60 7b [2] 27 6a [2] 69 66 [2] 65 6c [2] 72 67 [2] 69 29 [2] 54 }

  condition:
    any of them
}