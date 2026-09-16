rule TTP_XOR_MULT_DOSStub_4b19 {
  strings:
    $key_4b19 = { 1f 71 [2] 6b 69 [2] 2c 6b [2] 6b 7a [2] 25 76 [2] 29 7c [2] 3e 77 [2] 25 39 [2] 18 }

  condition:
    any of them
}