rule TTP_XOR_MULT_DOSStub_0b39 {
  strings:
    $key_0b39 = { 5f 51 [2] 2b 49 [2] 6c 4b [2] 2b 5a [2] 65 56 [2] 69 5c [2] 7e 57 [2] 65 19 [2] 58 }

  condition:
    any of them
}