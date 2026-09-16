rule TTP_XOR_MULT_DOSStub_3954 {
  strings:
    $key_3954 = { 6d 3c [2] 19 24 [2] 5e 26 [2] 19 37 [2] 57 3b [2] 5b 31 [2] 4c 3a [2] 57 74 [2] 6a }

  condition:
    any of them
}