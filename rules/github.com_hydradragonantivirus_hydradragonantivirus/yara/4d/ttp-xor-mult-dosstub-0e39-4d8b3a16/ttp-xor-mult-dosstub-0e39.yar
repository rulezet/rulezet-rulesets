rule TTP_XOR_MULT_DOSStub_0e39 {
  strings:
    $key_0e39 = { 5a 51 [2] 2e 49 [2] 69 4b [2] 2e 5a [2] 60 56 [2] 6c 5c [2] 7b 57 [2] 60 19 [2] 5d }

  condition:
    any of them
}