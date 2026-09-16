rule TTP_XOR_MULT_DOSStub_0a34 {
  strings:
    $key_0a34 = { 5e 5c [2] 2a 44 [2] 6d 46 [2] 2a 57 [2] 64 5b [2] 68 51 [2] 7f 5a [2] 64 14 [2] 59 }

  condition:
    any of them
}