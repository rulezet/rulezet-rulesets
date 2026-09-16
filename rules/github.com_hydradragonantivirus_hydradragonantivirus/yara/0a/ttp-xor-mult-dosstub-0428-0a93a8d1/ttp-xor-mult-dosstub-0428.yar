rule TTP_XOR_MULT_DOSStub_0428 {
  strings:
    $key_0428 = { 50 40 [2] 24 58 [2] 63 5a [2] 24 4b [2] 6a 47 [2] 66 4d [2] 71 46 [2] 6a 08 [2] 57 }

  condition:
    any of them
}