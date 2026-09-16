rule TTP_XOR_MULT_DOSStub_0e25 {
  strings:
    $key_0e25 = { 5a 4d [2] 2e 55 [2] 69 57 [2] 2e 46 [2] 60 4a [2] 6c 40 [2] 7b 4b [2] 60 05 [2] 5d }

  condition:
    any of them
}