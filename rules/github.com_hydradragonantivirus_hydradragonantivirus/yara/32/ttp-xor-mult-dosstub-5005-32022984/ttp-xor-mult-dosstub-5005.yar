rule TTP_XOR_MULT_DOSStub_5005 {
  strings:
    $key_5005 = { 04 6d [2] 70 75 [2] 37 77 [2] 70 66 [2] 3e 6a [2] 32 60 [2] 25 6b [2] 3e 25 [2] 03 }

  condition:
    any of them
}