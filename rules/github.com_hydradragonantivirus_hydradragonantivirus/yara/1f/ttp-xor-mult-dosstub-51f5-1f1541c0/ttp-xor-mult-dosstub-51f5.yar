rule TTP_XOR_MULT_DOSStub_51f5 {
  strings:
    $key_51f5 = { 05 9d [2] 71 85 [2] 36 87 [2] 71 96 [2] 3f 9a [2] 33 90 [2] 24 9b [2] 3f d5 [2] 02 }

  condition:
    any of them
}