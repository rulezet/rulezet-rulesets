rule TTP_XOR_MULT_DOSStub_0308 {
  strings:
    $key_0308 = { 57 60 [2] 23 78 [2] 64 7a [2] 23 6b [2] 6d 67 [2] 61 6d [2] 76 66 [2] 6d 28 [2] 50 }

  condition:
    any of them
}