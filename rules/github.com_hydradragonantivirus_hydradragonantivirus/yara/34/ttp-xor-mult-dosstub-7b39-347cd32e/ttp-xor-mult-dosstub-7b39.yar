rule TTP_XOR_MULT_DOSStub_7b39 {
  strings:
    $key_7b39 = { 2f 51 [2] 5b 49 [2] 1c 4b [2] 5b 5a [2] 15 56 [2] 19 5c [2] 0e 57 [2] 15 19 [2] 28 }

  condition:
    any of them
}