rule TTP_XOR_MULT_DOSStub_3532 {
  strings:
    $key_3532 = { 61 5a [2] 15 42 [2] 52 40 [2] 15 51 [2] 5b 5d [2] 57 57 [2] 40 5c [2] 5b 12 [2] 66 }

  condition:
    any of them
}