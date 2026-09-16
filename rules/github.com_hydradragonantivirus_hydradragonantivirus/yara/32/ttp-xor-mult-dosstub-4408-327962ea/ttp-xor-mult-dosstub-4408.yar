rule TTP_XOR_MULT_DOSStub_4408 {
  strings:
    $key_4408 = { 10 60 [2] 64 78 [2] 23 7a [2] 64 6b [2] 2a 67 [2] 26 6d [2] 31 66 [2] 2a 28 [2] 17 }

  condition:
    any of them
}