rule TTP_XOR_MULT_DOSStub_0919 {
  strings:
    $key_0919 = { 5d 71 [2] 29 69 [2] 6e 6b [2] 29 7a [2] 67 76 [2] 6b 7c [2] 7c 77 [2] 67 39 [2] 5a }

  condition:
    any of them
}