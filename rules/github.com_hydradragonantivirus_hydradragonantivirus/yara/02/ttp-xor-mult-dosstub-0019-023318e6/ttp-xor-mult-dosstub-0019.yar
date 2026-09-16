rule TTP_XOR_MULT_DOSStub_0019 {
  strings:
    $key_0019 = { 54 71 [2] 20 69 [2] 67 6b [2] 20 7a [2] 6e 76 [2] 62 7c [2] 75 77 [2] 6e 39 [2] 53 }

  condition:
    any of them
}