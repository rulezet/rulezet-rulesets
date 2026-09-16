rule TTP_XOR_MULT_DOSStub_1108 {
  strings:
    $key_1108 = { 45 60 [2] 31 78 [2] 76 7a [2] 31 6b [2] 7f 67 [2] 73 6d [2] 64 66 [2] 7f 28 [2] 42 }

  condition:
    any of them
}