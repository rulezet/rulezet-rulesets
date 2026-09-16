rule TTP_XOR_MULT_DOSStub_0a04 {
  strings:
    $key_0a04 = { 5e 6c [2] 2a 74 [2] 6d 76 [2] 2a 67 [2] 64 6b [2] 68 61 [2] 7f 6a [2] 64 24 [2] 59 }

  condition:
    any of them
}