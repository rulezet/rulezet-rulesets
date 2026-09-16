rule TTP_XOR_MULT_DOSStub_3959 {
  strings:
    $key_3959 = { 6d 31 [2] 19 29 [2] 5e 2b [2] 19 3a [2] 57 36 [2] 5b 3c [2] 4c 37 [2] 57 79 [2] 6a }

  condition:
    any of them
}