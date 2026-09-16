rule TTP_XOR_MULT_DOSStub_0e09 {
  strings:
    $key_0e09 = { 5a 61 [2] 2e 79 [2] 69 7b [2] 2e 6a [2] 60 66 [2] 6c 6c [2] 7b 67 [2] 60 29 [2] 5d }

  condition:
    any of them
}