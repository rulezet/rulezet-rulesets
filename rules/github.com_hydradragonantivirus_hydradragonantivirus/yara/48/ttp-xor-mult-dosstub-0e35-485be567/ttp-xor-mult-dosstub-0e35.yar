rule TTP_XOR_MULT_DOSStub_0e35 {
  strings:
    $key_0e35 = { 5a 5d [2] 2e 45 [2] 69 47 [2] 2e 56 [2] 60 5a [2] 6c 50 [2] 7b 5b [2] 60 15 [2] 5d }

  condition:
    any of them
}