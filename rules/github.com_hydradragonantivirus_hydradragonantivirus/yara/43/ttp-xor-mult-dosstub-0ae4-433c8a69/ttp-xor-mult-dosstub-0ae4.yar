rule TTP_XOR_MULT_DOSStub_0ae4 {
  strings:
    $key_0ae4 = { 5e 8c [2] 2a 94 [2] 6d 96 [2] 2a 87 [2] 64 8b [2] 68 81 [2] 7f 8a [2] 64 c4 [2] 59 }

  condition:
    any of them
}