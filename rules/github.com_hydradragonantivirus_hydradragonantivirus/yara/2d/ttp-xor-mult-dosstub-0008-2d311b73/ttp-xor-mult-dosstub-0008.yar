rule TTP_XOR_MULT_DOSStub_0008 {
  strings:
    $key_0008 = { 54 60 [2] 20 78 [2] 67 7a [2] 20 6b [2] 6e 67 [2] 62 6d [2] 75 66 [2] 6e 28 [2] 53 }

  condition:
    any of them
}