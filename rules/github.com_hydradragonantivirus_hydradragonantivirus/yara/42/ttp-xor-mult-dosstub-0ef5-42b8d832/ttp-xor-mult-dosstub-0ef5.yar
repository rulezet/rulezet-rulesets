rule TTP_XOR_MULT_DOSStub_0ef5 {
  strings:
    $key_0ef5 = { 5a 9d [2] 2e 85 [2] 69 87 [2] 2e 96 [2] 60 9a [2] 6c 90 [2] 7b 9b [2] 60 d5 [2] 5d }

  condition:
    any of them
}