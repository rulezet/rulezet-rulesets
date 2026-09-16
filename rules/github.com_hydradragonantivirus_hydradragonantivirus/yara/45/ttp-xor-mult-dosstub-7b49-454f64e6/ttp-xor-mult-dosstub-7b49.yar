rule TTP_XOR_MULT_DOSStub_7b49 {
  strings:
    $key_7b49 = { 2f 21 [2] 5b 39 [2] 1c 3b [2] 5b 2a [2] 15 26 [2] 19 2c [2] 0e 27 [2] 15 69 [2] 28 }

  condition:
    any of them
}