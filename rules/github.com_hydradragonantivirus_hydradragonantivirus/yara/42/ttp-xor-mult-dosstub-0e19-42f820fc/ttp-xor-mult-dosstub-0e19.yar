rule TTP_XOR_MULT_DOSStub_0e19 {
  strings:
    $key_0e19 = { 5a 71 [2] 2e 69 [2] 69 6b [2] 2e 7a [2] 60 76 [2] 6c 7c [2] 7b 77 [2] 60 39 [2] 5d }

  condition:
    any of them
}